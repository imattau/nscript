use crate::{
    Diagnostic, Import, RuntimeProfile, Span, Token, TokenKind,
    ast::{
        AstProgram, CapabilityDeclaration, EventDeclaration, EventField, EventModeSyntax, Expr,
        ExprKind, FunctionDeclaration, Item, LetDeclaration, MatchArm, Parameter, Pattern,
        PatternKind, Permission, SelectExpression, Spanned, Statement, StatementKind,
        StoreDeclaration, TypeRef,
    },
};

pub(crate) fn parse(tokens: &[Token]) -> (AstProgram, Vec<Diagnostic>) {
    let mut parser = Parser {
        tokens,
        index: 0,
        diagnostics: Vec::new(),
    };
    let items = parser.parse_items(None);
    (AstProgram { items }, parser.diagnostics)
}

struct Parser<'a> {
    tokens: &'a [Token],
    index: usize,
    diagnostics: Vec<Diagnostic>,
}

impl Parser<'_> {
    fn parse_items(&mut self, closing: Option<char>) -> Vec<Item> {
        let mut items = Vec::new();
        self.skip_terminators();
        while !self.at_end() && closing.is_none_or(|value| !self.at_symbol(value)) {
            let start = self.span();
            let item = match self.word() {
                Some("use") => self.parse_use().map(Item::Use),
                Some("runtime") => self.parse_runtime().map(Item::Runtime),
                Some("defaults") => self.parse_defaults(),
                Some("let" | "var") => self.parse_let().map(Item::Let),
                Some("fn") => self.parse_function().map(Item::Function),
                Some("event") => self.parse_event().map(Item::Event),
                Some("signer") => self.parse_capability().map(Item::Signer),
                Some("relay") => self.parse_capability().map(Item::Relay),
                Some("relayset") => self.parse_capability().map(Item::RelaySet),
                Some("store") => self.parse_store().map(Item::Store),
                Some("permissions") => self.parse_permissions(),
                Some("stream") => self.parse_stream(),
                _ => self.parse_statement().map(Item::Statement),
            };
            if let Some(item) = item {
                items.push(item);
            } else {
                self.recover_item();
            }
            if self.span() == start && !self.at_end() {
                self.index += 1;
            }
            self.skip_terminators();
        }
        if let Some(symbol) = closing {
            self.expect_symbol(symbol);
        }
        items
    }

    fn parse_use(&mut self) -> Option<Import> {
        let span = self.bump()?.span;
        let path = self.module_path()?;
        let requirement = if self.eat_symbol('@') {
            if let Some(value) = self.take_string() {
                Some(value.value)
            } else {
                let mut value = String::new();
                while !self.at_terminator() && !self.at_end() {
                    value.push_str(&self.token_text());
                    self.index += 1;
                }
                Some(value)
            }
        } else {
            None
        };
        self.terminator();
        Some(Import {
            path,
            requirement,
            span,
        })
    }

    fn parse_runtime(&mut self) -> Option<Spanned<RuntimeProfile>> {
        let start = self.bump()?.span;
        let (value, span) = if self.eat_word("standard") {
            (RuntimeProfile::Standard, self.previous_span())
        } else if self.eat_word("hardened") && self.eat_symbol('-') && self.eat_word("agent") {
            (
                RuntimeProfile::HardenedAgent,
                start.join(self.previous_span()),
            )
        } else {
            self.error(self.span(), "E1101", "unknown runtime profile");
            return None;
        };
        self.terminator();
        Some(Spanned { value, span })
    }

    fn parse_defaults(&mut self) -> Option<Item> {
        let start = self.bump()?.span;
        self.expect_symbol('{')?;
        let (mut signer, mut relays) = (None, None);
        self.skip_terminators();
        while !self.at_symbol('}') && !self.at_end() {
            let key = self.take_name()?;
            self.expect_symbol(':')?;
            let value = self.take_name()?;
            match key.value.as_str() {
                "signer" => signer = Some(value),
                "relays" => relays = Some(value),
                _ => self.error(key.span, "E1101", "unknown defaults entry"),
            }
            self.terminator();
            self.skip_terminators();
        }
        let end = self.expect_symbol('}')?;
        Some(Item::Defaults {
            signer,
            relays,
            span: start.join(end),
        })
    }

    fn parse_let(&mut self) -> Option<LetDeclaration> {
        let start = self.bump()?.span;
        let name = self.take_name()?;
        let type_annotation = self.eat_symbol(':').then(|| self.parse_type()).flatten();
        self.expect_symbol('=')?;
        let value = self.parse_expression(0)?;
        self.terminator();
        Some(LetDeclaration {
            name,
            type_annotation,
            span: start.join(value.span),
            value,
        })
    }

    fn parse_function(&mut self) -> Option<FunctionDeclaration> {
        let start = self.bump()?.span;
        let name = self.take_name()?;
        let parameters = self.parse_parameters()?;
        let return_type = if self.eat_symbol('-') {
            self.expect_symbol('>')?;
            self.parse_type()
        } else {
            None
        };
        self.expect_symbol('{')?;
        let body = self.parse_items(Some('}'));
        Some(FunctionDeclaration {
            name,
            parameters,
            return_type,
            body,
            span: start.join(self.previous_span()),
        })
    }

    fn parse_parameters(&mut self) -> Option<Vec<Parameter>> {
        self.expect_symbol('(')?;
        let mut output = Vec::new();
        while !self.at_symbol(')') && !self.at_end() {
            let name = self.take_name()?;
            self.expect_symbol(':')?;
            output.push(Parameter {
                name,
                type_ref: self.parse_type()?,
            });
            if !self.eat_symbol(',') {
                break;
            }
        }
        self.expect_symbol(')')?;
        Some(output)
    }

    fn parse_event(&mut self) -> Option<EventDeclaration> {
        let start = self.bump()?.span;
        let name = self.take_name()?;
        self.expect_symbol('{')?;
        self.skip_terminators();
        let (mut kind, mut mode, mut parameter) = (None, EventModeSyntax::Regular, None);
        let mut fields = Vec::new();
        while !self.at_symbol('}') && !self.at_end() {
            if self.eat_word("replaceable") {
                mode = EventModeSyntax::Replaceable;
            } else if self.eat_word("ephemeral") {
                mode = EventModeSyntax::Ephemeral;
            } else if self.eat_word("parameterised") {
                self.expect_word("by")?;
                parameter = Some(self.take_name()?);
                mode = EventModeSyntax::Parameterised;
            } else {
                let field = self.take_name()?;
                self.expect_symbol(':')?;
                if field.value == "kind" {
                    kind = self
                        .take_integer()
                        .and_then(|value| u16::try_from(value).ok());
                } else {
                    let type_ref = self.parse_type()?;
                    let default = self
                        .eat_symbol('=')
                        .then(|| self.parse_expression(0))
                        .flatten();
                    fields.push(EventField {
                        name: field,
                        type_ref,
                        default,
                    });
                }
            }
            self.terminator();
            self.skip_terminators();
        }
        let end = self.expect_symbol('}')?;
        Some(EventDeclaration {
            name,
            kind,
            mode,
            parameter,
            fields,
            span: start.join(end),
        })
    }

    fn parse_capability(&mut self) -> Option<CapabilityDeclaration> {
        let start = self.bump()?.span;
        let name = self.take_name()?;
        self.expect_symbol('=')?;
        let value = self.parse_expression(0)?;
        self.terminator();
        Some(CapabilityDeclaration {
            name,
            span: start.join(value.span),
            value,
        })
    }

    fn parse_store(&mut self) -> Option<StoreDeclaration> {
        let start = self.bump()?.span;
        let name = self.take_name()?;
        let (mut key_type, mut value_type) = (None, None);
        if self.eat_symbol('<') {
            let first = self.parse_type()?;
            if self.eat_symbol(',') {
                key_type = Some(first);
                value_type = self.parse_type();
            } else {
                value_type = Some(first);
            }
            self.expect_symbol('>')?;
        } else if self.eat_symbol('{') {
            self.skip_terminators();
            while !self.at_symbol('}') && !self.at_end() {
                let field = self.take_name()?;
                self.expect_symbol(':')?;
                let ty = self.parse_type()?;
                if field.value == "key" {
                    key_type = Some(ty);
                } else if field.value == "value" {
                    value_type = Some(ty);
                }
                self.terminator();
                self.skip_terminators();
            }
            self.expect_symbol('}')?;
        }
        self.terminator();
        Some(StoreDeclaration {
            name,
            key_type,
            value_type: value_type.unwrap_or(TypeRef {
                name: "Unit".to_owned(),
                arguments: Vec::new(),
                span: start,
            }),
            span: start.join(self.previous_span()),
        })
    }

    fn parse_permissions(&mut self) -> Option<Item> {
        let start = self.bump()?.span;
        self.expect_symbol('{')?;
        self.skip_terminators();
        let mut permissions = Vec::new();
        while !self.at_symbol('}') && !self.at_end() {
            let operation = self.take_name()?;
            let permission = match operation.value.as_str() {
                "read" | "publish" => {
                    let event = self.parse_type()?;
                    let relayset = if self.eat_word(if operation.value == "read" {
                        "from"
                    } else {
                        "to"
                    }) {
                        Some(self.take_name()?)
                    } else {
                        None
                    };
                    if operation.value == "read" {
                        Permission::Read { event, relayset }
                    } else {
                        Permission::Publish { event, relayset }
                    }
                }
                "sign" => Permission::Sign {
                    event: self.parse_type()?,
                    signer: if self.eat_word("with") {
                        Some(self.take_name()?)
                    } else {
                        None
                    },
                },
                "encrypt" | "decrypt" => Permission::Typed {
                    target: self.parse_type()?,
                    capability: if self.eat_word("with") {
                        Some(self.take_name()?)
                    } else {
                        None
                    },
                    operation,
                },
                "http" => Permission::Http(self.take_string()?),
                _ => {
                    let argument = if self.at_terminator() {
                        None
                    } else {
                        self.take_name()
                    };
                    Permission::Named {
                        operation,
                        argument,
                    }
                }
            };
            permissions.push(permission);
            self.terminator();
            self.skip_terminators();
        }
        let end = self.expect_symbol('}')?;
        Some(Item::Permissions(Spanned {
            value: permissions,
            span: start.join(end),
        }))
    }

    fn parse_stream(&mut self) -> Option<Item> {
        let start = self.bump()?.span;
        let name = self.take_name()?;
        self.expect_symbol('=')?;
        let value = self.parse_expression(0)?;
        self.terminator();
        Some(Item::Stream {
            name,
            span: start.join(value.span),
            value,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn parse_statement(&mut self) -> Option<Statement> {
        let start = self.span();
        let value = match self.word() {
            Some("return") => {
                self.index += 1;
                let value = (!self.at_terminator())
                    .then(|| self.parse_expression(0))
                    .flatten();
                StatementKind::Return(value)
            }
            Some("for") => {
                self.index += 1;
                let binding = self.take_name()?;
                self.expect_word("in")?;
                let value = self.parse_expression(0)?;
                let body = self.parse_block()?;
                StatementKind::For {
                    binding,
                    value,
                    body,
                }
            }
            Some("if") => {
                self.index += 1;
                let condition = self.parse_expression(0)?;
                let then_body = self.parse_block()?;
                let else_body = if self.eat_word("else") {
                    self.parse_block()?
                } else {
                    Vec::new()
                };
                StatementKind::If {
                    condition,
                    then_body,
                    else_body,
                }
            }
            Some("on") => {
                self.index += 1;
                let source = self.parse_control_expression()?;
                let predicate = if self.eat_word("where") {
                    self.parse_expression(0)
                } else {
                    None
                };
                let body = self.parse_block()?;
                StatementKind::On {
                    source,
                    predicate,
                    body,
                }
            }
            Some("once") => {
                self.index += 1;
                self.expect_symbol('(')?;
                let key = self.parse_expression(0)?;
                self.expect_symbol(')')?;
                StatementKind::Once {
                    key,
                    body: self.parse_block()?,
                }
            }
            Some("every") => {
                self.index += 1;
                let duration = self.parse_expression(0)?;
                StatementKind::Every {
                    duration,
                    body: self.parse_block()?,
                }
            }
            Some("at") => {
                self.index += 1;
                let schedule = self.parse_expression(0)?;
                StatementKind::At {
                    schedule,
                    body: self.parse_block()?,
                }
            }
            Some("send") => {
                self.index += 1;
                let value = self.parse_expression(0)?;
                let value = if self.eat_word("to") {
                    let recipient = self.parse_expression(0)?;
                    let span = value.span.join(recipient.span);
                    let message = Spanned {
                        value: ExprKind::Construct {
                            name: Spanned {
                                value: "PrivateMessage".to_owned(),
                                span,
                            },
                            fields: vec![
                                (
                                    Spanned {
                                        value: "content".to_owned(),
                                        span,
                                    },
                                    value,
                                ),
                                (
                                    Spanned {
                                        value: "recipient".to_owned(),
                                        span,
                                    },
                                    recipient,
                                ),
                            ],
                        },
                        span,
                    };
                    Spanned {
                        value: ExprKind::Call {
                            callee: Box::new(Spanned {
                                value: ExprKind::Member {
                                    value: Box::new(Spanned {
                                        value: ExprKind::Identifier("nip17".to_owned()),
                                        span,
                                    }),
                                    name: Spanned {
                                        value: "send_private".to_owned(),
                                        span,
                                    },
                                },
                                span,
                            }),
                            arguments: vec![message],
                        },
                        span,
                    }
                } else {
                    value
                };
                let signer = if self.eat_word("with") {
                    self.parse_expression(0)
                } else {
                    None
                };
                StatementKind::Send { value, signer }
            }
            Some("reply") => {
                self.index += 1;
                let content = self.parse_expression(0)?;
                if !self.eat_word("to") {
                    return None;
                }
                let target = self.parse_expression(0)?;
                let span = content.span.join(target.span);
                let reply = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Reply".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "target".to_owned(),
                                    span,
                                },
                                target.clone(),
                            ),
                            (
                                Spanned {
                                    value: "root".to_owned(),
                                    span,
                                },
                                target,
                            ),
                            (
                                Spanned {
                                    value: "content".to_owned(),
                                    span,
                                },
                                content,
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip10".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_reply".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![reply],
                    },
                    span,
                })
            }
            Some("repost") => {
                self.index += 1;
                let target = self.parse_expression(0)?;
                let span = target.span;
                let repost = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Repost".to_owned(),
                            span,
                        },
                        fields: vec![(
                            Spanned {
                                value: "target".to_owned(),
                                span,
                            },
                            target,
                        )],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip18".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_repost".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![repost],
                    },
                    span,
                })
            }
            Some("delete") => {
                self.index += 1;
                let target = self.parse_expression(0)?;
                let span = target.span;
                let request = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "DeletionRequest".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "target".to_owned(),
                                    span,
                                },
                                target,
                            ),
                            (
                                Spanned {
                                    value: "reason".to_owned(),
                                    span,
                                },
                                Spanned {
                                    value: ExprKind::Text(String::new()),
                                    span,
                                },
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip09".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "request_deletion".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![request],
                    },
                    span,
                })
            }
            Some("comment") => {
                self.index += 1;
                let content = self.parse_expression(0)?;
                if !self.eat_word("on") {
                    return None;
                }
                let target = self.parse_expression(0)?;
                let span = content.span.join(target.span);
                let comment = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Comment".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "target".to_owned(),
                                    span,
                                },
                                target,
                            ),
                            (
                                Spanned {
                                    value: "content".to_owned(),
                                    span,
                                },
                                content,
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip22".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_comment".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![comment],
                    },
                    span,
                })
            }
            Some("report") => {
                self.index += 1;
                let target = self.parse_expression(0)?;
                if !self.eat_word("as") {
                    return None;
                }
                let category = self.parse_expression(0)?;
                let span = target.span.join(category.span);
                let report = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Report".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "target".to_owned(),
                                    span,
                                },
                                target,
                            ),
                            (
                                Spanned {
                                    value: "category".to_owned(),
                                    span,
                                },
                                category,
                            ),
                            (
                                Spanned {
                                    value: "content".to_owned(),
                                    span,
                                },
                                Spanned {
                                    value: ExprKind::Text(String::new()),
                                    span,
                                },
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip56".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_report".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![report],
                    },
                    span,
                })
            }
            Some("label") => {
                self.index += 1;
                let target = self.parse_expression(0)?;
                if !self.eat_word("as") {
                    return None;
                }
                let value = self.parse_expression(0)?;
                let span = target.span.join(value.span);
                let label = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Label".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "target".to_owned(),
                                    span,
                                },
                                target,
                            ),
                            (
                                Spanned {
                                    value: "namespace".to_owned(),
                                    span,
                                },
                                Spanned {
                                    value: ExprKind::Text("nscript".to_owned()),
                                    span,
                                },
                            ),
                            (
                                Spanned {
                                    value: "value".to_owned(),
                                    span,
                                },
                                value,
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip32".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_label".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![label],
                    },
                    span,
                })
            }
            Some("status") => {
                self.index += 1;
                let status = self.parse_expression(0)?;
                let span = status.span;
                let user_status = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "UserStatus".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "status".to_owned(),
                                    span,
                                },
                                status,
                            ),
                            (
                                Spanned {
                                    value: "content".to_owned(),
                                    span,
                                },
                                Spanned {
                                    value: ExprKind::Text(String::new()),
                                    span,
                                },
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip38".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_status".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![user_status],
                    },
                    span,
                })
            }
            Some("draft") => {
                self.index += 1;
                let identifier = self.parse_expression(0)?;
                if !self.eat_word("with") {
                    return None;
                }
                let content = self.parse_expression(0)?;
                let span = identifier.span.join(content.span);
                let draft = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Draft".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "identifier".to_owned(),
                                    span,
                                },
                                identifier,
                            ),
                            (
                                Spanned {
                                    value: "content".to_owned(),
                                    span,
                                },
                                content,
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip37".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "save_draft".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![draft],
                    },
                    span,
                })
            }
            Some("badge") => {
                self.index += 1;
                let identifier = self.parse_expression(0)?;
                if !self.eat_word("as") {
                    return None;
                }
                let name = self.parse_expression(0)?;
                let span = identifier.span.join(name.span);
                let badge = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Badge".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "identifier".to_owned(),
                                    span,
                                },
                                identifier,
                            ),
                            (
                                Spanned {
                                    value: "name".to_owned(),
                                    span,
                                },
                                name,
                            ),
                            (
                                Spanned {
                                    value: "description".to_owned(),
                                    span,
                                },
                                Spanned {
                                    value: ExprKind::Text(String::new()),
                                    span,
                                },
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip58".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_badge".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![badge],
                    },
                    span,
                })
            }
            Some("highlight") => {
                self.index += 1;
                let content = self.parse_expression(0)?;
                if !self.eat_word("from") {
                    return None;
                }
                let source = self.parse_expression(0)?;
                let span = content.span.join(source.span);
                let highlight = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Highlight".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "source".to_owned(),
                                    span,
                                },
                                source,
                            ),
                            (
                                Spanned {
                                    value: "content".to_owned(),
                                    span,
                                },
                                content,
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip84".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_highlight".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![highlight],
                    },
                    span,
                })
            }
            Some("search") => {
                self.index += 1;
                let _event = self.parse_type()?;
                if !self.eat_word("for") {
                    return None;
                }
                let query = self.parse_expression(0)?;
                let span = query.span;
                let request = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "SearchRequest".to_owned(),
                            span,
                        },
                        fields: vec![(
                            Spanned {
                                value: "query".to_owned(),
                                span,
                            },
                            query,
                        )],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip50".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "search_events".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![request],
                    },
                    span,
                })
            }
            Some("react") => {
                self.index += 1;
                let content = self.parse_expression(0)?;
                if !self.eat_word("to") {
                    return None;
                }
                let target = self.parse_expression(0)?;
                let span = content.span.join(target.span);
                let reaction = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Reaction".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "target".to_owned(),
                                    span,
                                },
                                target,
                            ),
                            (
                                Spanned {
                                    value: "content".to_owned(),
                                    span,
                                },
                                content,
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip25".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_reaction".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![reaction],
                    },
                    span,
                })
            }
            Some("zap") => {
                self.index += 1;
                let recipient = self.parse_expression(0)?;
                if !self.eat_word("amount") {
                    return None;
                }
                let amount = self.parse_expression(0)?;
                let span = recipient.span.join(amount.span);
                let request = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "ZapRequest".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "recipient".to_owned(),
                                    span,
                                },
                                recipient,
                            ),
                            (
                                Spanned {
                                    value: "amount".to_owned(),
                                    span,
                                },
                                amount,
                            ),
                            (
                                Spanned {
                                    value: "message".to_owned(),
                                    span,
                                },
                                Spanned {
                                    value: ExprKind::Text(String::new()),
                                    span,
                                },
                            ),
                        ],
                    },
                    span,
                };
                StatementKind::Expression(Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(Spanned {
                            value: ExprKind::Member {
                                value: Box::new(Spanned {
                                    value: ExprKind::Identifier("nip57".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "create_zap_request".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![request],
                    },
                    span,
                })
            }
            _ => StatementKind::Expression(self.parse_expression(0)?),
        };
        self.terminator();
        Some(Spanned {
            value,
            span: start.join(self.previous_span()),
        })
    }

    fn parse_block(&mut self) -> Option<Vec<Item>> {
        self.expect_symbol('{')?;
        Some(self.parse_items(Some('}')))
    }

    fn parse_control_expression(&mut self) -> Option<Expr> {
        if self.word().is_some()
            && matches!(
                self.tokens.get(self.index + 1).map(|token| &token.kind),
                Some(TokenKind::Symbol('{'))
            )
        {
            let name = self.take_name()?;
            Some(Spanned {
                value: ExprKind::Identifier(name.value),
                span: name.span,
            })
        } else {
            self.parse_expression(0)
        }
    }

    fn parse_expression(&mut self, minimum: u8) -> Option<Expr> {
        self.skip_expression_newlines();
        let mut left = self.parse_prefix()?;
        loop {
            self.skip_expression_newlines();
            if self.at_symbol('(') {
                let arguments = self.parse_arguments()?;
                let span = left.span.join(self.previous_span());
                left = Spanned {
                    value: ExprKind::Call {
                        callee: Box::new(left),
                        arguments,
                    },
                    span,
                };
                continue;
            }
            if self.eat_symbol('.') {
                let name = self.take_name()?;
                let span = left.span.join(name.span);
                left = Spanned {
                    value: ExprKind::Member {
                        value: Box::new(left),
                        name,
                    },
                    span,
                };
                continue;
            }
            if self.eat_symbol('?') {
                let span = left.span.join(self.previous_span());
                left = Spanned {
                    value: ExprKind::Propagate(Box::new(left)),
                    span,
                };
                continue;
            }
            let Some((operator, precedence, right_associative)) = self.binary_operator() else {
                break;
            };
            if precedence < minimum {
                break;
            }
            self.consume_operator(&operator);
            let right = self.parse_expression(if right_associative {
                precedence
            } else {
                precedence + 1
            })?;
            let span = left.span.join(right.span);
            left = if operator == "=" {
                Spanned {
                    value: ExprKind::Assign {
                        target: Box::new(left),
                        value: Box::new(right),
                    },
                    span,
                }
            } else {
                Spanned {
                    value: ExprKind::Binary {
                        operator,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    span,
                }
            };
        }
        Some(left)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_prefix(&mut self) -> Option<Expr> {
        let start = self.span();
        if self.eat_word("true") || self.eat_word("false") {
            return Some(Spanned {
                value: ExprKind::Bool(self.previous_word() == "true"),
                span: start,
            });
        }
        if self.eat_word("none") {
            return Some(Spanned {
                value: ExprKind::None,
                span: start,
            });
        }
        if let Some(text) = self.take_string_if() {
            return Some(Spanned {
                value: ExprKind::Text(text),
                span: start,
            });
        }
        if let Some(number) = self.take_integer_if() {
            if self.eat_symbol('.') {
                let fraction = self.take_integer()?;
                return Some(Spanned {
                    value: ExprKind::Decimal(format!("{number}.{fraction}")),
                    span: start.join(self.previous_span()),
                });
            }
            if matches!(self.word(), Some("ms" | "s" | "m" | "h" | "d" | "w")) {
                let unit = self.word()?.to_owned();
                self.index += 1;
                return Some(Spanned {
                    value: ExprKind::Duration {
                        value: number,
                        unit,
                    },
                    span: start.join(self.previous_span()),
                });
            }
            if self.eat_symbol('%') {
                return Some(Spanned {
                    value: ExprKind::Percentage(number),
                    span: start.join(self.previous_span()),
                });
            }
            return Some(Spanned {
                value: ExprKind::Integer(i64::try_from(number).unwrap_or(i64::MAX)),
                span: start,
            });
        }
        if self.eat_word("not") || self.eat_symbol('-') {
            let operator = self.previous_word_or_symbol();
            let value = self.parse_expression(8)?;
            return Some(Spanned {
                span: start.join(value.span),
                value: ExprKind::Unary {
                    operator,
                    value: Box::new(value),
                },
            });
        }
        if self.eat_word("select") {
            return self.parse_select(start);
        }
        if self.eat_word("sign") {
            let value = self.parse_expression(0)?;
            self.expect_word("with")?;
            let signer = self.parse_expression(0)?;
            return Some(Spanned {
                span: start.join(signer.span),
                value: ExprKind::Sign {
                    value: Box::new(value),
                    signer: Box::new(signer),
                },
            });
        }
        if self.eat_word("publish") {
            return self.parse_publish(start);
        }
        if self.eat_word("fetch") {
            let format = self.take_name()?.value;
            self.expect_word("from")?;
            let url = self.parse_expression(0)?;
            return Some(Spanned {
                span: start.join(url.span),
                value: ExprKind::Fetch {
                    format,
                    url: Box::new(url),
                },
            });
        }
        if self.eat_word("latest") {
            return self.parse_latest(start);
        }
        if self.eat_word("match") {
            return self.parse_match(start);
        }
        if self.eat_symbol('(') {
            let value = self.parse_expression(0)?;
            self.expect_symbol(')')?;
            return Some(value);
        }
        if self.eat_symbol('[') {
            let values = self.parse_comma_expressions(']')?;
            return Some(Spanned {
                value: ExprKind::List(values),
                span: start.join(self.previous_span()),
            });
        }
        if self.eat_symbol('{') {
            let fields = self.parse_fields()?;
            return Some(Spanned {
                value: ExprKind::Record(fields),
                span: start.join(self.previous_span()),
            });
        }
        let name = self.take_name()?;
        if self.eat_symbol('{') {
            let fields = self.parse_fields()?;
            return Some(Spanned {
                span: start.join(self.previous_span()),
                value: ExprKind::Construct { name, fields },
            });
        }
        Some(Spanned {
            value: ExprKind::Identifier(name.value),
            span: name.span,
        })
    }

    fn parse_select(&mut self, start: Span) -> Option<Expr> {
        let event = self.parse_type()?;
        let mut select = SelectExpression {
            event,
            predicate: None,
            since: None,
            until: None,
            limit: None,
            relays: None,
        };
        loop {
            self.skip_expression_newlines();
            match self.word() {
                Some("where") => {
                    self.index += 1;
                    select.predicate = Some(Box::new(self.parse_expression(0)?));
                }
                Some("since") => {
                    self.index += 1;
                    select.since = Some(Box::new(self.parse_expression(0)?));
                }
                Some("until") => {
                    self.index += 1;
                    select.until = Some(Box::new(self.parse_expression(0)?));
                }
                Some("limit") => {
                    self.index += 1;
                    select.limit = self.take_integer_if();
                }
                Some("from") => {
                    self.index += 1;
                    select.relays = Some(Box::new(self.parse_expression(0)?));
                }
                _ => break,
            }
        }
        Some(Spanned {
            value: ExprKind::Select(select),
            span: start.join(self.previous_span()),
        })
    }

    fn parse_publish(&mut self, start: Span) -> Option<Expr> {
        let value = self.parse_expression(0)?;
        let relays = if self.eat_word("to") {
            Some(Box::new(self.parse_expression(0)?))
        } else {
            None
        };
        let signer = if self.eat_word("with") {
            Some(Box::new(self.parse_expression(0)?))
        } else {
            None
        };
        let end = signer
            .as_ref()
            .or(relays.as_ref())
            .map_or(value.span, |item| item.span);
        Some(Spanned {
            value: ExprKind::Publish {
                value: Box::new(value),
                relays,
                signer,
            },
            span: start.join(end),
        })
    }

    fn parse_latest(&mut self, start: Span) -> Option<Expr> {
        let event = self.parse_type()?;
        let arguments = self.parse_arguments()?;
        let relays = if self.eat_word("from") {
            Some(Box::new(self.parse_expression(0)?))
        } else {
            None
        };
        Some(Spanned {
            value: ExprKind::Latest {
                event,
                arguments,
                relays,
            },
            span: start.join(self.previous_span()),
        })
    }

    fn parse_match(&mut self, start: Span) -> Option<Expr> {
        let value = if self.word().is_some()
            && matches!(
                self.tokens.get(self.index + 1).map(|token| &token.kind),
                Some(TokenKind::Symbol('{'))
            ) {
            let name = self.take_name()?;
            Spanned {
                value: ExprKind::Identifier(name.value),
                span: name.span,
            }
        } else {
            self.parse_expression(0)?
        };
        self.expect_symbol('{')?;
        self.skip_terminators();
        let mut arms = Vec::new();
        while !self.at_symbol('}') && !self.at_end() {
            let pattern = self.parse_pattern()?;
            let guard = if self.eat_word("if") {
                self.parse_expression(0)
            } else {
                None
            };
            self.expect_symbol('=')?;
            self.expect_symbol('>')?;
            let arm_value = self.parse_expression(0)?;
            arms.push(MatchArm {
                pattern,
                guard,
                value: arm_value,
            });
            self.eat_symbol(',');
            self.skip_terminators();
        }
        self.expect_symbol('}')?;
        Some(Spanned {
            value: ExprKind::Match {
                value: Box::new(value),
                arms,
            },
            span: start.join(self.previous_span()),
        })
    }

    fn parse_pattern(&mut self) -> Option<Pattern> {
        let start = self.span();
        let name = self.take_name()?;
        if name.value == "_" {
            return Some(Spanned {
                value: PatternKind::Wildcard,
                span: name.span,
            });
        }
        if self.eat_symbol('(') {
            let mut values = Vec::new();
            while !self.at_symbol(')') {
                values.push(self.parse_pattern()?);
                if !self.eat_symbol(',') {
                    break;
                }
            }
            self.expect_symbol(')')?;
            return Some(Spanned {
                value: PatternKind::Variant {
                    name: name.value,
                    values,
                },
                span: start.join(self.previous_span()),
            });
        }
        Some(Spanned {
            value: PatternKind::Binding(name.value),
            span: name.span,
        })
    }

    fn parse_arguments(&mut self) -> Option<Vec<Expr>> {
        self.expect_symbol('(')?;
        self.parse_comma_expressions(')')
    }

    fn parse_comma_expressions(&mut self, closing: char) -> Option<Vec<Expr>> {
        let mut values = Vec::new();
        self.skip_expression_newlines();
        while !self.at_symbol(closing) && !self.at_end() {
            values.push(self.parse_expression(0)?);
            self.skip_expression_newlines();
            if !self.eat_symbol(',') {
                break;
            }
            self.skip_expression_newlines();
        }
        self.expect_symbol(closing)?;
        Some(values)
    }

    fn parse_fields(&mut self) -> Option<Vec<(Spanned<String>, Expr)>> {
        let mut fields = Vec::new();
        self.skip_expression_newlines();
        while !self.at_symbol('}') && !self.at_end() {
            let name = self.take_name()?;
            self.expect_symbol(':')?;
            fields.push((name, self.parse_expression(0)?));
            self.skip_expression_newlines();
            if !self.eat_symbol(',') && !self.at_terminator() {
                break;
            }
            self.skip_terminators();
        }
        self.expect_symbol('}')?;
        Some(fields)
    }

    fn parse_type(&mut self) -> Option<TypeRef> {
        let name = self.take_name()?;
        let mut arguments = Vec::new();
        if self.eat_symbol('<') {
            loop {
                arguments.push(self.parse_type()?);
                if !self.eat_symbol(',') {
                    break;
                }
            }
            self.expect_symbol('>')?;
        }
        Some(TypeRef {
            name: name.value,
            arguments,
            span: name.span.join(self.previous_span()),
        })
    }

    fn module_path(&mut self) -> Option<String> {
        let mut path = self.take_name()?.value;
        while self.eat_symbol(':') {
            self.expect_symbol(':')?;
            path.push_str("::");
            path.push_str(&self.take_name()?.value);
        }
        Some(path)
    }

    fn binary_operator(&self) -> Option<(String, u8, bool)> {
        let one =
            self.word()
                .map(str::to_owned)
                .or_else(|| match self.tokens.get(self.index)?.kind {
                    TokenKind::Symbol(c) => Some(c.to_string()),
                    _ => None,
                })?;
        let (op, precedence, right) = match one.as_str() {
            "=" if self.symbol(self.index + 1) == Some('=') => ("==", 3, false),
            "!" if self.symbol(self.index + 1) == Some('=') => ("!=", 3, false),
            "<" if self.symbol(self.index + 1) == Some('=') => ("<=", 4, false),
            ">" if self.symbol(self.index + 1) == Some('=') => (">=", 4, false),
            "=" => ("=", 1, true),
            "or" => ("or", 2, false),
            "and" => ("and", 3, false),
            "<" | ">" | "in" | "contains" => (one.as_str(), 4, false),
            "+" | "-" => (one.as_str(), 5, false),
            "*" | "/" | "%" => (one.as_str(), 6, false),
            _ => return None,
        };
        Some((op.to_owned(), precedence, right))
    }

    fn consume_operator(&mut self, operator: &str) {
        self.index += 1 + usize::from(operator.len() == 2 && !matches!(operator, "or" | "in"));
    }
    fn symbol(&self, index: usize) -> Option<char> {
        match self.tokens.get(index)?.kind {
            TokenKind::Symbol(c) => Some(c),
            _ => None,
        }
    }
    fn at_end(&self) -> bool {
        self.index >= self.tokens.len()
    }
    fn word(&self) -> Option<&str> {
        match &self.tokens.get(self.index)?.kind {
            TokenKind::Identifier(v) => Some(v),
            _ => None,
        }
    }
    fn span(&self) -> Span {
        self.tokens.get(self.index).map_or_else(
            || self.tokens.last().map_or(Span::default(), |t| t.span),
            |t| t.span,
        )
    }
    fn previous_span(&self) -> Span {
        self.index
            .checked_sub(1)
            .and_then(|i| self.tokens.get(i))
            .map_or(Span::default(), |t| t.span)
    }
    fn previous_word(&self) -> &str {
        self.index
            .checked_sub(1)
            .and_then(|i| self.tokens.get(i))
            .and_then(|t| match &t.kind {
                TokenKind::Identifier(v) => Some(v.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }
    fn previous_word_or_symbol(&self) -> String {
        self.index
            .checked_sub(1)
            .and_then(|i| self.tokens.get(i))
            .map_or(String::new(), |t| match &t.kind {
                TokenKind::Identifier(v) => v.clone(),
                TokenKind::Symbol(c) => c.to_string(),
                _ => String::new(),
            })
    }
    fn bump(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.index);
        self.index += usize::from(token.is_some());
        token
    }
    fn eat_word(&mut self, value: &str) -> bool {
        if self.word() == Some(value) {
            self.index += 1;
            true
        } else {
            false
        }
    }
    fn eat_symbol(&mut self, value: char) -> bool {
        if self.at_symbol(value) {
            self.index += 1;
            true
        } else {
            false
        }
    }
    fn at_symbol(&self, value: char) -> bool {
        self.symbol(self.index) == Some(value)
    }
    fn at_terminator(&self) -> bool {
        matches!(
            self.tokens.get(self.index).map(|t| &t.kind),
            Some(TokenKind::Newline | TokenKind::Symbol(';'))
        )
    }
    fn take_name(&mut self) -> Option<Spanned<String>> {
        let token = self.tokens.get(self.index)?.clone();
        if let TokenKind::Identifier(value) = token.kind {
            self.index += 1;
            Some(Spanned {
                value,
                span: token.span,
            })
        } else {
            self.error(token.span, "E1101", "expected an identifier");
            None
        }
    }
    fn take_string(&mut self) -> Option<Spanned<String>> {
        let token = self.tokens.get(self.index)?.clone();
        if let TokenKind::String(value) = token.kind {
            self.index += 1;
            Some(Spanned {
                value,
                span: token.span,
            })
        } else {
            self.error(token.span, "E1101", "expected a string");
            None
        }
    }
    fn take_string_if(&mut self) -> Option<String> {
        match self.tokens.get(self.index).cloned()?.kind {
            TokenKind::String(v) => {
                self.index += 1;
                Some(v)
            }
            _ => None,
        }
    }
    fn take_integer(&mut self) -> Option<u64> {
        self.take_integer_if().or_else(|| {
            self.error(self.span(), "E1101", "expected an integer");
            None
        })
    }
    fn take_integer_if(&mut self) -> Option<u64> {
        match self.tokens.get(self.index).cloned()?.kind {
            TokenKind::Number(v) => {
                self.index += 1;
                v.replace('_', "").parse().ok()
            }
            _ => None,
        }
    }
    fn token_text(&self) -> String {
        match self.tokens.get(self.index).map(|t| &t.kind) {
            Some(TokenKind::Identifier(v) | TokenKind::Number(v) | TokenKind::String(v)) => {
                v.clone()
            }
            Some(TokenKind::Symbol(c)) => c.to_string(),
            _ => String::new(),
        }
    }
    fn expect_word(&mut self, value: &str) -> Option<Span> {
        if self.eat_word(value) {
            Some(self.previous_span())
        } else {
            self.error(self.span(), "E1101", format!("expected `{value}`"));
            None
        }
    }
    fn expect_symbol(&mut self, value: char) -> Option<Span> {
        if self.eat_symbol(value) {
            Some(self.previous_span())
        } else {
            self.error(self.span(), "E1101", format!("expected `{value}`"));
            None
        }
    }
    fn terminator(&mut self) {
        if self.at_terminator() {
            self.skip_terminators();
        }
    }
    fn skip_terminators(&mut self) {
        while self.at_terminator() {
            self.index += 1;
        }
    }
    fn skip_expression_newlines(&mut self) {
        while matches!(
            self.tokens.get(self.index).map(|t| &t.kind),
            Some(TokenKind::Newline)
        ) {
            self.index += 1;
        }
    }
    fn recover_item(&mut self) {
        while !self.at_end() && !self.at_terminator() && !self.at_symbol('}') {
            self.index += 1;
        }
    }
    fn error(&mut self, span: Span, code: &'static str, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            code,
            message: message.into(),
            span,
        });
    }
}

trait SpanJoin {
    fn join(self, other: Self) -> Self;
}
impl SpanJoin for Span {
    fn join(self, other: Self) -> Self {
        if self == Span::default() {
            return other;
        }
        if other == Span::default() {
            return self;
        }
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            line: self.line,
            column: self.column,
        }
    }
}
