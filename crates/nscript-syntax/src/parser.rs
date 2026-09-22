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
        newline_ends_expression: false,
    };
    let items = parser.parse_items(None);
    (AstProgram { items }, parser.diagnostics)
}

/// Statement keywords that introduce a Layer 3 intent form (`docs/LAYER3.md`).
pub(crate) const LAYER3_FORMS: [&str; 26] = [
    "send",
    "reply",
    "repost",
    "delete",
    "comment",
    "report",
    "label",
    "status",
    "draft",
    "badge",
    "highlight",
    "assert",
    "calendar",
    "live",
    "image",
    "video",
    "file",
    "upload",
    "handler",
    "search",
    "react",
    "say",
    "zap",
    "kick",
    "ban",
    "on",
];

struct Parser<'a> {
    tokens: &'a [Token],
    index: usize,
    diagnostics: Vec<Diagnostic>,
    /// While parsing a `match` arm's value, a newline ends the expression, so
    /// the next line can start a new arm (`-3 => ..` is a pattern, not a
    /// subtraction from the previous value). Reset inside brackets, where a
    /// newline is just whitespace.
    newline_ends_expression: bool,
}

impl Parser<'_> {
    fn parse_items(&mut self, closing: Option<char>) -> Vec<Item> {
        let mut items = Vec::new();
        self.skip_terminators();
        while !self.at_end() && closing.is_none_or(|value| !self.at_symbol(value)) {
            let start = self.span();
            let diagnostics_before = self.diagnostics.len();
            let first_token = self.token_text();
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
                Some("key") => self.parse_key(),
                Some("store") => self.parse_store().map(Item::Store),
                Some("permissions") => self.parse_permissions(),
                Some("stream") => self.parse_stream(),
                _ => self.parse_statement().map(Item::Statement),
            };
            if let Some(item) = item {
                items.push(item);
                // A statement must end where the line does. Leftover tokens
                // would otherwise become extra statements: `kick alice bob`
                // would silently kick `alice` and ignore `bob`.
                if !self.statement_ended(closing) {
                    let junk = self.token_text();
                    self.error(
                        self.span(),
                        "E1101",
                        format!("unexpected `{junk}`; end a statement with a newline or `;`"),
                    );
                    self.recover_item();
                }
            } else {
                // A parser that gives up without a word must not let the
                // statement vanish: every path that fails reports something.
                if self.diagnostics.len() == diagnostics_before {
                    let first = first_token.clone();
                    self.error(
                        start,
                        "E1101",
                        format!("could not parse the statement starting at `{first}`"),
                    );
                }
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

    /// `key name = host("label")`. The label names a key the host provisions;
    /// the script only ever holds an opaque handle to it.
    fn parse_key(&mut self) -> Option<Item> {
        let declaration = self.parse_capability()?;
        let ExprKind::Call { callee, arguments } = &declaration.value.value else {
            self.error(
                declaration.value.span,
                "E1101",
                "a key is declared `key name = host(\"label\")`",
            );
            return None;
        };
        let is_host = matches!(&callee.value, ExprKind::Identifier(name) if name == "host");
        let labelled = matches!(arguments.as_slice(), [argument] if matches!(argument.value, ExprKind::Text(_)));
        if !is_host || !labelled {
            self.error(
                declaration.value.span,
                "E1101",
                "a key is declared `key name = host(\"label\")`",
            );
            return None;
        }
        Some(Item::Key(declaration))
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

    /// Parses an expression, reporting `E1101` if it is absent. A Layer 3
    /// statement that fails to parse is otherwise dropped without a trace, and
    /// a moderation statement must never fail silently.
    fn expression_or_error(&mut self, minimum: u8, expected: &str) -> Option<Expr> {
        let before = self.diagnostics.len();
        let parsed = self.parse_expression(minimum);
        if parsed.is_none() && self.diagnostics.len() == before {
            self.error(self.span(), "E1101", format!("expected {expected}"));
        }
        parsed
    }

    /// `module.operation(arguments)` as an expression node, the shape every
    /// Layer 3 form lowers to.
    fn module_call(module: &str, operation: &str, arguments: Vec<Expr>, span: Span) -> Expr {
        Spanned {
            value: ExprKind::Call {
                callee: Box::new(Spanned {
                    value: ExprKind::Member {
                        value: Box::new(Spanned {
                            value: ExprKind::Identifier(module.to_owned()),
                            span,
                        }),
                        name: Spanned {
                            value: operation.to_owned(),
                            span,
                        },
                    },
                    span,
                }),
                arguments,
            },
            span,
        }
    }

    /// A record literal `Name { field: value; ... }`.
    fn construct(name: &str, fields: Vec<(&str, Expr)>, span: Span) -> Expr {
        Spanned {
            value: ExprKind::Construct {
                name: Spanned {
                    value: name.to_owned(),
                    span,
                },
                fields: fields
                    .into_iter()
                    .map(|(field, value)| {
                        (
                            Spanned {
                                value: field.to_owned(),
                                span,
                            },
                            value,
                        )
                    })
                    .collect(),
            },
            span,
        }
    }

    /// Parses a statement. A Layer 3 form that fails to parse must say so: the
    /// item loop discards a `None` without a trace, which would let a script
    /// that means to `kick`, `send` or `zap` check clean and do nothing.
    fn parse_statement(&mut self) -> Option<Statement> {
        let form = self
            .word()
            .and_then(|word| LAYER3_FORMS.iter().find(|form| **form == word))
            .copied();
        let start = self.span();
        let before = self.diagnostics.len();
        let parsed = self.parse_statement_inner();
        if let Some(form) = form
            && parsed.is_none()
            && self.diagnostics.len() == before
        {
            self.error(start, "E1101", format!("incomplete `{form}` statement"));
        }
        parsed
    }

    #[allow(clippy::too_many_lines)]
    fn parse_statement_inner(&mut self) -> Option<Statement> {
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
            Some("assert") => {
                self.index += 1;
                let subject = self.parse_expression(0)?;
                if !self.eat_word("as") {
                    return None;
                }
                let kind = self.parse_expression(0)?;
                if !self.eat_word("value") {
                    return None;
                }
                let value = self.parse_expression(0)?;
                let span = subject.span.join(value.span);
                let assertion = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "Assertion".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "subject".to_owned(),
                                    span,
                                },
                                subject,
                            ),
                            (
                                Spanned {
                                    value: "kind".to_owned(),
                                    span,
                                },
                                kind,
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
                                    value: ExprKind::Identifier("nip85".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_assertion".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![assertion],
                    },
                    span,
                })
            }
            Some("calendar") => {
                self.index += 1;
                let title = self.parse_expression(0)?;
                if !self.eat_word("from") {
                    return None;
                }
                let start = self.parse_expression(0)?;
                if !self.eat_word("to") {
                    return None;
                }
                let end = self.parse_expression(0)?;
                if !self.eat_word("at") {
                    return None;
                }
                let location = self.parse_expression(0)?;
                let span = title.span.join(location.span);
                let event = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "CalendarEvent".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "title".to_owned(),
                                    span,
                                },
                                title,
                            ),
                            (
                                Spanned {
                                    value: "start".to_owned(),
                                    span,
                                },
                                start,
                            ),
                            (
                                Spanned {
                                    value: "end".to_owned(),
                                    span,
                                },
                                end,
                            ),
                            (
                                Spanned {
                                    value: "location".to_owned(),
                                    span,
                                },
                                location,
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
                                    value: ExprKind::Identifier("nip52".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_calendar_event".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![event],
                    },
                    span,
                })
            }
            Some("live") => {
                self.index += 1;
                let identifier = self.parse_expression(0)?;
                if !self.eat_word("titled") {
                    return None;
                }
                let title = self.parse_expression(0)?;
                if !self.eat_word("about") {
                    return None;
                }
                let summary = self.parse_expression(0)?;
                let span = identifier.span.join(summary.span);
                let event = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "LiveEvent".to_owned(),
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
                                    value: "title".to_owned(),
                                    span,
                                },
                                title,
                            ),
                            (
                                Spanned {
                                    value: "summary".to_owned(),
                                    span,
                                },
                                summary,
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
                                    value: ExprKind::Identifier("nip53".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_live_event".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![event],
                    },
                    span,
                })
            }
            Some("image") => {
                self.index += 1;
                let url = self.parse_expression(0)?;
                if !self.eat_word("caption") {
                    return None;
                }
                let caption = self.parse_expression(0)?;
                let span = url.span.join(caption.span);
                let event = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "ImageEvent".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "url".to_owned(),
                                    span,
                                },
                                url,
                            ),
                            (
                                Spanned {
                                    value: "caption".to_owned(),
                                    span,
                                },
                                caption,
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
                                    value: ExprKind::Identifier("nip68".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_image".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![event],
                    },
                    span,
                })
            }
            Some("video") => {
                self.index += 1;
                let url = self.parse_expression(0)?;
                if !self.eat_word("caption") {
                    return None;
                }
                let caption = self.parse_expression(0)?;
                let span = url.span.join(caption.span);
                let event = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "VideoEvent".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "url".to_owned(),
                                    span,
                                },
                                url,
                            ),
                            (
                                Spanned {
                                    value: "caption".to_owned(),
                                    span,
                                },
                                caption,
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
                                    value: ExprKind::Identifier("nip71".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_video".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![event],
                    },
                    span,
                })
            }
            Some("file") => {
                self.index += 1;
                let url = self.parse_expression(0)?;
                if !self.eat_word("mime") {
                    return None;
                }
                let mime = self.parse_expression(0)?;
                if !self.eat_word("hash") {
                    return None;
                }
                let hash = self.parse_expression(0)?;
                let span = url.span.join(hash.span);
                let file = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "FileMetadata".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "url".to_owned(),
                                    span,
                                },
                                url,
                            ),
                            (
                                Spanned {
                                    value: "mime".to_owned(),
                                    span,
                                },
                                mime,
                            ),
                            (
                                Spanned {
                                    value: "hash".to_owned(),
                                    span,
                                },
                                hash,
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
                                    value: ExprKind::Identifier("nip94".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_file_metadata".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![file],
                    },
                    span,
                })
            }
            Some("upload") => {
                self.index += 1;
                let url = self.parse_expression(0)?;
                if !self.eat_word("hash") {
                    return None;
                }
                let hash = self.parse_expression(0)?;
                if !self.eat_word("size") {
                    return None;
                }
                let size = self.parse_expression(0)?;
                let span = url.span.join(size.span);
                let upload = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "BlobUpload".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "url".to_owned(),
                                    span,
                                },
                                url,
                            ),
                            (
                                Spanned {
                                    value: "hash".to_owned(),
                                    span,
                                },
                                hash,
                            ),
                            (
                                Spanned {
                                    value: "size".to_owned(),
                                    span,
                                },
                                size,
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
                                    value: ExprKind::Identifier("nipb7".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "upload_blob".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![upload],
                    },
                    span,
                })
            }
            Some("handler") => {
                self.index += 1;
                let kind = self.parse_expression(0)?;
                if !self.eat_word("for") {
                    return None;
                }
                let app = self.parse_expression(0)?;
                if !self.eat_word("at") {
                    return None;
                }
                let endpoint = self.parse_expression(0)?;
                let span = kind.span.join(endpoint.span);
                let handler = Spanned {
                    value: ExprKind::Construct {
                        name: Spanned {
                            value: "AppHandler".to_owned(),
                            span,
                        },
                        fields: vec![
                            (
                                Spanned {
                                    value: "kind".to_owned(),
                                    span,
                                },
                                kind,
                            ),
                            (
                                Spanned {
                                    value: "app".to_owned(),
                                    span,
                                },
                                app,
                            ),
                            (
                                Spanned {
                                    value: "endpoint".to_owned(),
                                    span,
                                },
                                endpoint,
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
                                    value: ExprKind::Identifier("nip89".to_owned()),
                                    span,
                                }),
                                name: Spanned {
                                    value: "publish_handler".to_owned(),
                                    span,
                                },
                            },
                            span,
                        }),
                        arguments: vec![handler],
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
            // Concord Layer 3: moderation and stream posting intent, lowered to
            // the typed `concord04` / `concord01` module operations.
            Some(word @ ("kick" | "ban")) => {
                let verb = word.to_owned();
                let operation = if verb == "kick" {
                    "kick_member"
                } else {
                    "ban_member"
                };
                self.index += 1;
                let target = self.expression_or_error(0, &format!("a member to {verb}"))?;
                let span = target.span;
                StatementKind::Expression(Self::module_call(
                    "concord04",
                    operation,
                    vec![target],
                    span,
                ))
            }
            Some("say") => {
                self.index += 1;
                // Above `in`'s precedence, so the separator is not swallowed
                // as a membership test.
                let content = self.expression_or_error(5, "the message to say")?;
                self.expect_word("in")?;
                let stream = self.expression_or_error(0, "the stream to say it in")?;
                let span = content.span.join(stream.span);
                // `me` is the program's principal; the host refuses to publish
                // as anyone else.
                let author = Spanned {
                    value: ExprKind::Identifier("me".to_owned()),
                    span,
                };
                let message = Self::construct(
                    "StreamMessage",
                    vec![("author", author), ("content", content)],
                    span,
                );
                StatementKind::Expression(Self::module_call(
                    "concord01",
                    "publish_message",
                    vec![stream, message],
                    span,
                ))
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
            let crossed_newline = self.skip_expression_newlines_noting();
            if crossed_newline && self.newline_ends_expression {
                break;
            }
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
            let value =
                self.with_newline_ends_expression(false, |parser| parser.parse_expression(0))?;
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
        // Record types are capitalised (`Note { .. }`), so only a capitalised
        // name opens a record literal. A lowercase name before `{` is a
        // variable with a block after it: `if ready { .. }`.
        if name.value.chars().next().is_some_and(char::is_uppercase) && self.eat_symbol('{') {
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
            // Above assignment's precedence: the `=` of `=>` must not be read as
            // an assignment operator inside the guard.
            let guard = if self.eat_word("if") {
                Some(self.expression_or_error(2, "a guard condition")?)
            } else {
                None
            };
            self.expect_symbol('=')?;
            self.expect_symbol('>')?;
            let arm_value =
                self.with_newline_ends_expression(true, |parser| parser.parse_expression(0))?;
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

    /// Whether the next tokens start a literal pattern: a string, a number, a
    /// negative number, `true`, `false` or `none`.
    fn at_literal_pattern(&self) -> bool {
        matches!(self.word(), Some("true" | "false" | "none"))
            || matches!(
                self.tokens.get(self.index).map(|token| &token.kind),
                Some(TokenKind::String(_) | TokenKind::Number(_))
            )
            || (self.at_symbol('-')
                && matches!(
                    self.tokens.get(self.index + 1).map(|token| &token.kind),
                    Some(TokenKind::Number(_))
                ))
    }

    /// A literal pattern: any literal the language has (string, integer,
    /// decimal, duration, percentage, `true`, `false`, `none`), read by the
    /// expression parser so the two cannot disagree, with an optional leading
    /// minus on a number.
    fn parse_literal_pattern(&mut self) -> Option<Pattern> {
        let start = self.span();
        let negative = self.eat_symbol('-');
        let literal = self.parse_prefix()?;
        let value = match (negative, literal.value) {
            (false, value) => value,
            (true, ExprKind::Integer(number)) => ExprKind::Integer(number.checked_neg()?),
            (true, ExprKind::Decimal(text)) => ExprKind::Decimal(format!("-{text}")),
            (true, _) => {
                self.error(
                    start,
                    "E1101",
                    "only an integer or decimal can be negated in a pattern",
                );
                return None;
            }
        };
        Some(Spanned {
            value: PatternKind::Literal(value),
            span: start.join(self.previous_span()),
        })
    }

    /// `pattern_fields` of a record pattern: `{ author, content: c }`.
    fn parse_pattern_fields(&mut self) -> Option<Vec<(String, Option<Pattern>)>> {
        let mut fields = Vec::new();
        self.skip_expression_newlines();
        while !self.at_symbol('}') && !self.at_end() {
            let field = self.take_name()?;
            let pattern = if self.eat_symbol(':') {
                Some(self.parse_pattern()?)
            } else {
                None
            };
            fields.push((field.value, pattern));
            self.skip_expression_newlines();
            if !self.eat_symbol(',') && !self.at_terminator() {
                break;
            }
            self.skip_terminators();
        }
        self.expect_symbol('}')?;
        Some(fields)
    }

    /// The patterns of the language (`spec/grammar.ebnf`): `_`, a literal, a
    /// binding, a variant `Ok(x)`, or a record `Note { author, content: c }`.
    /// A capitalised name with no payload (`None`) is a unit variant, not a
    /// binding: bindings are lowercase, as types are capitalised.
    fn parse_pattern(&mut self) -> Option<Pattern> {
        if self.at_literal_pattern() {
            return self.parse_literal_pattern();
        }
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
        if self.eat_symbol('{') {
            let fields = self.parse_pattern_fields()?;
            return Some(Spanned {
                value: PatternKind::Record {
                    name: name.value,
                    fields,
                },
                span: start.join(self.previous_span()),
            });
        }
        if name.value.chars().next().is_some_and(char::is_uppercase) {
            return Some(Spanned {
                value: PatternKind::Variant {
                    name: name.value,
                    values: Vec::new(),
                },
                span: name.span,
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
        self.with_newline_ends_expression(false, |parser| {
            parser.parse_comma_expressions_inner(closing)
        })
    }

    fn parse_comma_expressions_inner(&mut self, closing: char) -> Option<Vec<Expr>> {
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
        self.with_newline_ends_expression(false, Self::parse_fields_inner)
    }

    fn parse_fields_inner(&mut self) -> Option<Vec<(Spanned<String>, Expr)>> {
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
        self.skip_expression_newlines_noting();
    }

    /// Skips newlines, reporting whether there were any.
    fn skip_expression_newlines_noting(&mut self) -> bool {
        let start = self.index;
        while matches!(
            self.tokens.get(self.index).map(|t| &t.kind),
            Some(TokenKind::Newline)
        ) {
            self.index += 1;
        }
        self.index > start
    }

    /// Runs `parse` with newlines ending expressions (or not). A `match` arm's
    /// value ends at its line; brackets inside it turn that back off.
    fn with_newline_ends_expression<T>(
        &mut self,
        ends: bool,
        parse: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let saved = std::mem::replace(&mut self.newline_ends_expression, ends);
        let result = parse(self);
        self.newline_ends_expression = saved;
        result
    }
    /// Whether the statement just parsed ended cleanly: at the end of input, a
    /// terminator, the enclosing block's closing symbol, or right after a
    /// terminator or block-closing `}` that its parser already consumed.
    fn statement_ended(&self, closing: Option<char>) -> bool {
        if self.at_end() || self.at_terminator() {
            return true;
        }
        if closing.is_some_and(|symbol| self.at_symbol(symbol)) {
            return true;
        }
        self.index
            .checked_sub(1)
            .and_then(|previous| self.tokens.get(previous))
            .is_some_and(|token| {
                matches!(
                    token.kind,
                    TokenKind::Newline | TokenKind::Symbol(';' | '}')
                )
            })
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
