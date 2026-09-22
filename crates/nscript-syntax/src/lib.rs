//! Lexical and structural parsing for `NScript` source files.

use std::collections::BTreeSet;

use unicode_ident::{is_xid_continue, is_xid_start};

pub mod ast;
mod parser;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceId(pub u32);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Severity {
    #[default]
    Error,
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Label {
    pub source: SourceId,
    pub span: Span,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredDiagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    pub primary: Label,
    pub secondary: Vec<Label>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Identifier(String),
    Number(String),
    String(String),
    Symbol(char),
    Newline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeProfile {
    #[default]
    Standard,
    HardenedAgent,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Defaults {
    pub signer: Option<(String, Span)>,
    pub relays: Option<(String, Span)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishSite {
    pub span: Span,
    pub explicit_signer: bool,
    pub explicit_relays: bool,
    pub requires_signer: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Import {
    pub path: String,
    pub requirement: Option<String>,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct Program {
    pub ast: ast::AstProgram,
    pub profile: RuntimeProfile,
    pub profile_span: Option<Span>,
    pub defaults: Defaults,
    pub signers: BTreeSet<String>,
    pub relaysets: BTreeSet<String>,
    pub identifiers: Vec<(String, Span)>,
    pub imports: Vec<Import>,
    pub publishes: Vec<PublishSite>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
    pub span: Span,
}

impl Diagnostic {
    #[must_use]
    pub fn structured(&self, source: SourceId) -> StructuredDiagnostic {
        StructuredDiagnostic {
            code: self.code,
            severity: Severity::Error,
            message: redact_sensitive(&self.message),
            primary: Label {
                source,
                span: self.span,
                message: self.message.clone(),
            },
            secondary: Vec::new(),
            notes: Vec::new(),
        }
    }
}

#[must_use]
pub fn redact_sensitive(value: &str) -> String {
    if value.contains("SecretKey") || value.contains("Nsec") {
        "[redacted sensitive value]".to_owned()
    } else {
        value.to_owned()
    }
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn lex(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = source.char_indices().peekable();
    let (mut line, mut column) = (1, 1);

    while let Some((start, character)) = chars.next() {
        let start_column = column;
        match character {
            ' ' | '\t' | '\r' => column += 1,
            '\n' => {
                tokens.push(Token {
                    kind: TokenKind::Newline,
                    span: Span {
                        start,
                        end: start + 1,
                        line,
                        column,
                    },
                });
                line += 1;
                column = 1;
            }
            '/' if matches!(chars.peek(), Some((_, '/'))) => {
                chars.next();
                column += 2;
                while let Some((_, next)) = chars.peek() {
                    if *next == '\n' {
                        break;
                    }
                    chars.next();
                    column += 1;
                }
            }
            '"' => {
                column += 1;
                let value_start = start + 1;
                let mut value_end = value_start;
                let mut escaped = false;
                for (offset, next) in chars.by_ref() {
                    if !escaped && next == '"' {
                        value_end = offset;
                        column += 1;
                        break;
                    }
                    if next == '\n' {
                        line += 1;
                        column = 1;
                    } else {
                        column += 1;
                    }
                    value_end = offset + next.len_utf8();
                    escaped = !escaped && next == '\\';
                    if next != '\\' {
                        escaped = false;
                    }
                }
                let end = chars.peek().map_or(source.len(), |(offset, _)| *offset);
                tokens.push(Token {
                    kind: TokenKind::String(source[value_start..value_end].to_owned()),
                    span: Span {
                        start,
                        end,
                        line,
                        column: start_column,
                    },
                });
            }
            character if character == '_' || is_xid_start(character) => {
                column += 1;
                let mut end = start + character.len_utf8();
                while let Some((offset, next)) = chars.peek() {
                    if !is_xid_continue(*next) {
                        break;
                    }
                    end = *offset + next.len_utf8();
                    chars.next();
                    column += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Identifier(source[start..end].to_owned()),
                    span: Span {
                        start,
                        end,
                        line,
                        column: start_column,
                    },
                });
            }
            character if character.is_ascii_digit() => {
                column += 1;
                let mut end = start + 1;
                while let Some((offset, next)) = chars.peek() {
                    if !(next.is_ascii_digit() || *next == '_') {
                        break;
                    }
                    end = *offset + 1;
                    chars.next();
                    column += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Number(source[start..end].to_owned()),
                    span: Span {
                        start,
                        end,
                        line,
                        column: start_column,
                    },
                });
            }
            symbol => {
                column += 1;
                tokens.push(Token {
                    kind: TokenKind::Symbol(symbol),
                    span: Span {
                        start,
                        end: start + symbol.len_utf8(),
                        line,
                        column: start_column,
                    },
                });
            }
        }
    }
    tokens
}

#[must_use]
pub fn parse_program(source: &str) -> (Program, Vec<Diagnostic>) {
    let tokens = lex(source);
    let (ast, mut diagnostics) = parser::parse(&tokens);
    let mut program = Program {
        ast,
        ..Program::default()
    };
    let mut index = 0;

    for token in &tokens {
        if let TokenKind::Identifier(name) = &token.kind {
            program.identifiers.push((name.clone(), token.span));
        }
    }

    while index < tokens.len() {
        let Some(keyword) = identifier_at(&tokens, index) else {
            index += 1;
            continue;
        };
        match keyword {
            "use" => {
                if let Some(import) = parse_import(&tokens, index) {
                    program.imports.push(import);
                }
            }
            "runtime" => {
                if let Some((name, token_index)) = next_identifier(&tokens, index + 1) {
                    program.profile_span = Some(tokens[token_index].span);
                    match name {
                        "standard" => program.profile = RuntimeProfile::Standard,
                        "hardened" if symbol_at(&tokens, token_index + 1, '-') => {
                            if let Some(("agent", _)) = next_identifier(&tokens, token_index + 2) {
                                program.profile = RuntimeProfile::HardenedAgent;
                            }
                        }
                        _ => diagnostics.push(Diagnostic {
                            code: "E1101",
                            message: format!("unknown runtime profile `{name}`"),
                            span: tokens[token_index].span,
                        }),
                    }
                }
            }
            "signer" => {
                if let Some((name, _)) = next_identifier(&tokens, index + 1) {
                    program.signers.insert(name.to_owned());
                }
            }
            "relayset" => {
                if let Some((name, _)) = next_identifier(&tokens, index + 1) {
                    program.relaysets.insert(name.to_owned());
                }
            }
            "defaults" => parse_defaults(&tokens, index, &mut program.defaults),
            "permissions" => {
                if let Some(end) = block_end(&tokens, index + 1) {
                    index = end;
                }
            }
            "publish" => program.publishes.push(parse_publish(&tokens, index)),
            _ => {}
        }
        index += 1;
    }
    (program, diagnostics)
}

fn parse_import(tokens: &[Token], start: usize) -> Option<Import> {
    let span = tokens.get(start)?.span;
    let (first, mut index) = next_identifier(tokens, start + 1)?;
    let mut path = first.to_owned();
    index += 1;
    while symbol_at(tokens, index, ':') && symbol_at(tokens, index + 1, ':') {
        let (segment, segment_index) = next_identifier(tokens, index + 2)?;
        path.push_str("::");
        path.push_str(segment);
        index = segment_index + 1;
    }
    let requirement = if symbol_at(tokens, index, '@') {
        index += 1;
        if let Some(TokenKind::String(value)) = tokens.get(index).map(|token| &token.kind) {
            Some(value.clone())
        } else {
            let mut value = String::new();
            while let Some(token) = tokens.get(index) {
                match &token.kind {
                    TokenKind::Newline | TokenKind::Symbol(';') => break,
                    TokenKind::Identifier(part) | TokenKind::Number(part) => {
                        value.push_str(part);
                    }
                    TokenKind::Symbol(part) => value.push(*part),
                    TokenKind::String(part) => value.push_str(part),
                }
                index += 1;
            }
            (!value.is_empty()).then_some(value)
        }
    } else {
        None
    };
    Some(Import {
        path,
        requirement,
        span,
    })
}

fn parse_defaults(tokens: &[Token], start: usize, defaults: &mut Defaults) {
    let mut index = start + 1;
    let mut depth = 0;
    while index < tokens.len() {
        if symbol_at(tokens, index, '{') {
            depth += 1;
        } else if symbol_at(tokens, index, '}') {
            if depth == 1 {
                break;
            }
            depth -= 1;
        } else if depth == 1
            && let Some(key) = identifier_at(tokens, index)
            && matches!(key, "signer" | "relays")
            && let Some((value, value_index)) = next_identifier(tokens, index + 1)
        {
            let entry = Some((value.to_owned(), tokens[value_index].span));
            if key == "signer" {
                defaults.signer = entry;
            } else {
                defaults.relays = entry;
            }
        }
        index += 1;
    }
}

fn parse_publish(tokens: &[Token], start: usize) -> PublishSite {
    let mut index = start + 1;
    while matches!(
        tokens.get(index).map(|token| &token.kind),
        Some(TokenKind::Newline)
    ) {
        index += 1;
    }
    let requires_signer = identifier_at(tokens, index)
        .and_then(|name| name.chars().next())
        .is_some_and(char::is_uppercase);
    let mut depth = 0_i32;
    let (mut explicit_signer, mut explicit_relays) = (false, false);
    while index < tokens.len() {
        match &tokens[index].kind {
            TokenKind::Symbol('{') => depth += 1,
            TokenKind::Symbol('}') => depth -= 1,
            TokenKind::Newline if depth == 0 => break,
            TokenKind::Identifier(name) if depth == 0 && name == "with" => {
                explicit_signer = true;
            }
            TokenKind::Identifier(name) if depth == 0 && name == "to" => {
                explicit_relays = true;
            }
            _ => {}
        }
        index += 1;
    }
    PublishSite {
        span: tokens[start].span,
        explicit_signer,
        explicit_relays,
        requires_signer,
    }
}

fn identifier_at(tokens: &[Token], index: usize) -> Option<&str> {
    match &tokens.get(index)?.kind {
        TokenKind::Identifier(value) => Some(value),
        _ => None,
    }
}

fn next_identifier(tokens: &[Token], mut index: usize) -> Option<(&str, usize)> {
    while index < tokens.len() {
        match &tokens[index].kind {
            TokenKind::Identifier(value) => return Some((value, index)),
            TokenKind::Newline => return None,
            _ => index += 1,
        }
    }
    None
}

fn symbol_at(tokens: &[Token], index: usize, expected: char) -> bool {
    matches!(tokens.get(index).map(|token| &token.kind), Some(TokenKind::Symbol(symbol)) if *symbol == expected)
}

fn block_end(tokens: &[Token], start: usize) -> Option<usize> {
    let mut depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.kind {
            TokenKind::Symbol('{') => depth += 1,
            TokenKind::Symbol('}') if depth == 1 => return Some(index),
            TokenKind::Symbol('}') if depth > 1 => depth -= 1,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::ast::{ExprKind, Item, PatternKind, StatementKind};
    use super::{RuntimeProfile, TokenKind, lex, parse_program};

    /// Renders an expression compactly so a lowering can be asserted exactly.
    fn render(expr: &super::ast::Expr) -> String {
        match &expr.value {
            ExprKind::Identifier(name) => name.clone(),
            ExprKind::Text(text) => format!("{text:?}"),
            ExprKind::Member { value, name } => format!("{}.{}", render(value), name.value),
            ExprKind::Call { callee, arguments } => {
                let arguments: Vec<_> = arguments.iter().map(render).collect();
                format!("{}({})", render(callee), arguments.join(", "))
            }
            ExprKind::Construct { name, fields } => {
                let fields: Vec<_> = fields
                    .iter()
                    .map(|(field, value)| format!("{}: {}", field.value, render(value)))
                    .collect();
                format!("{} {{ {} }}", name.value, fields.join("; "))
            }
            ExprKind::List(items) => {
                let items: Vec<_> = items.iter().map(render).collect();
                format!("[{}]", items.join(", "))
            }
            other => format!("{other:?}"),
        }
    }

    /// The lowering of the first top-level statement of `source`.
    fn lowered(source: &str) -> String {
        let (program, diagnostics) = parse_program(source);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        match &program.ast.items[0] {
            Item::Statement(statement) => match &statement.value {
                StatementKind::Expression(expr) => render(expr),
                other => panic!("not an expression statement: {other:?}"),
            },
            other => panic!("not a statement: {other:?}"),
        }
    }

    #[test]
    fn lexes_unicode_xid_identifiers() {
        let tokens = lex("let café = 1\nlet 東京 = café\n");
        let identifiers = tokens
            .iter()
            .filter_map(|token| match &token.kind {
                TokenKind::Identifier(value) => Some(value.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(identifiers, ["let", "café", "let", "東京", "café"]);
    }

    #[test]
    fn parses_profile_defaults_and_publish() {
        let source = r#"
runtime hardened-agent
signer account = nip46()
relayset public = configured
defaults { signer: account; relays: public }
publish Note { content: "hello" }
"#;
        let (program, diagnostics) = parse_program(source);
        assert!(diagnostics.is_empty());
        assert_eq!(program.profile, RuntimeProfile::HardenedAgent);
        assert_eq!(program.defaults.signer.as_ref().unwrap().0, "account");
        assert_eq!(program.defaults.relays.as_ref().unwrap().0, "public");
        assert!(program.publishes[0].requires_signer);
    }

    #[test]
    fn does_not_treat_permission_as_publication() {
        let source = "permissions { publish Note to public }\n";
        let (program, diagnostics) = parse_program(source);
        assert!(diagnostics.is_empty());
        assert!(program.publishes.is_empty());
    }

    #[test]
    fn parses_qualified_versioned_imports() {
        let (program, diagnostics) = parse_program("use community::moderation @ \"^2\"\n");
        assert!(diagnostics.is_empty());
        assert_eq!(program.imports[0].path, "community::moderation");
        assert_eq!(program.imports[0].requirement.as_deref(), Some("^2"));
    }

    #[test]
    fn concord_layer3_forms_lower_to_typed_module_operations() {
        assert_eq!(lowered("kick alice\n"), "concord04.kick_member(alice)");
        assert_eq!(lowered("ban alice\n"), "concord04.ban_member(alice)");
        assert_eq!(
            lowered("say \"hi\" in chat\n"),
            "concord01.publish_message(chat, StreamMessage { author: me; content: \"hi\" })"
        );
    }

    #[test]
    fn nip_layer3_forms_lower_to_typed_module_operations() {
        assert_eq!(
            lowered("article \"post-1\" titled \"T\" content \"body\"\n"),
            "nip23.publish_article(Article { identifier: \"post-1\"; title: \"T\"; content: \"body\" })"
        );
        assert_eq!(
            lowered("message \"hi\" in \"general\"\n"),
            "nip29.publish_group_message(GroupMessage { group: \"general\"; content: \"hi\" })"
        );
        assert_eq!(
            lowered("deploy \"example.com\" from \"dist/\"\n"),
            "nip5a.publish_site(SiteDeployment { domain: \"example.com\"; source: \"dist/\" })"
        );
        assert_eq!(
            lowered("save \"prefs\" as \"dark\"\n"),
            "nip78.publish_app_data(AppData { identifier: \"prefs\"; content: \"dark\" })"
        );
        assert_eq!(
            lowered("relays read [\"wss://a\"] write [\"wss://b\"]\n"),
            "nip65.publish_relay_list(RelayList { read: [\"wss://a\"]; write: [\"wss://b\"] })"
        );
        assert_eq!(
            lowered("follow [alice, bob]\n"),
            "nip02.publish_follow_list(FollowList { people: [alice, bob] })"
        );
    }

    #[test]
    fn say_keeps_compound_content_and_stops_at_in() {
        // `in` is a membership operator elsewhere; here it is the separator.
        let (program, diagnostics) = parse_program("say \"a\" + \"b\" in chat\n");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let Item::Statement(statement) = &program.ast.items[0] else {
            panic!("statement");
        };
        let StatementKind::Expression(expr) = &statement.value else {
            panic!("expression");
        };
        let ExprKind::Call { arguments, .. } = &expr.value else {
            panic!("call");
        };
        assert_eq!(
            render(&arguments[0]),
            "chat",
            "the stream is what follows `in`"
        );
        let ExprKind::Construct { fields, .. } = &arguments[1].value else {
            panic!("message record");
        };
        assert!(
            format!("{:?}", fields[1].1.value).contains("Binary"),
            "the content is the whole `\"a\" + \"b\"` expression"
        );
    }

    #[test]
    fn incomplete_concord_forms_are_diagnosed_not_guessed() {
        // `say` needs its stream, and `kick` its target.
        for source in ["say \"hi\"\n", "kick\n", "ban\n"] {
            let (_, diagnostics) = parse_program(source);
            assert!(!diagnostics.is_empty(), "{source:?} should not parse");
        }
    }

    #[test]
    fn concord_words_stay_ordinary_names_outside_statement_position() {
        let (program, diagnostics) = parse_program("let ban = 1\nlet kick = ban\nprint(kick)\n");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(program.ast.items.len(), 3);
    }

    #[test]
    fn every_incomplete_layer3_form_is_diagnosed() {
        // A bare keyword is the smallest incomplete statement of each form.
        for form in crate::parser::LAYER3_FORMS {
            let (_, diagnostics) = parse_program(&format!("{form}\n"));
            assert!(
                diagnostics.iter().any(|d| d.code == "E1101"),
                "`{form}` alone was accepted silently: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn older_forms_missing_a_required_part_are_diagnosed() {
        // `send "hi"` alone is a valid form (it lowers a bare value), so only
        // forms that truly need a second part belong here.
        for source in ["react \"x\"\n", "zap alice\n", "report event_target\n"] {
            let (_, diagnostics) = parse_program(source);
            assert!(
                diagnostics.iter().any(|d| d.code == "E1101"),
                "{source:?} accepted silently"
            );
        }
    }

    #[test]
    fn complete_layer3_forms_still_parse_without_diagnostics() {
        for source in [
            "send \"hi\" to alice\n",
            "react \"x\" to event_target\n",
            "repost event_to_repost\n",
            "zap alice amount 1000\n",
            "search Note for \"nostr\"\n",
            "kick alice\n",
            "say \"hi\" in chat\n",
        ] {
            let (_, diagnostics) = parse_program(source);
            assert!(diagnostics.is_empty(), "{source:?}: {diagnostics:?}");
        }
    }

    #[test]
    fn a_form_that_already_explains_itself_is_not_reported_twice() {
        let (_, diagnostics) = parse_program("say \"hi\"\n");
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    }

    #[test]
    fn statements_that_used_to_vanish_are_now_errors() {
        for source in [
            "foo bar baz\n", // leftover tokens were extra statements
            "123 456\n",
            "\"a string\" more\n",
            "kick alice bob\n", // would have kicked alice and ignored bob
            "let x =\n",        // a declaration with no value
            "x =\n",            // an assignment with no right side
            "5 +\n",            // a dangling operator
            "relayset x =\n",
        ] {
            let (_, diagnostics) = parse_program(source);
            assert!(
                diagnostics.iter().any(|d| d.code == "E1101"),
                "{source:?} was accepted silently"
            );
        }
    }

    #[test]
    fn leftover_tokens_are_reported_once_per_statement() {
        let (_, diagnostics) = parse_program("kick alice extra tokens here\n");
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert!(diagnostics[0].message.contains("unexpected `extra`"));
    }

    #[test]
    fn well_formed_statement_boundaries_are_still_accepted() {
        for source in [
            "let a = 1; let b = 2\n", // `;` separates statements
            "let a = 1\nlet b = 2\n", // so does a newline
            "if true { print(1) }\n", // a block's closing brace ends its last statement
            "if true { print(1); print(2) }\n",
            "fn f() { return 1 }\nlet x = f()\n",
            "on Note { print(event.content) }\n",
            "kick alice; ban bob\n",
            "let a = 1", // end of input ends a statement
        ] {
            let (_, diagnostics) = parse_program(source);
            assert!(diagnostics.is_empty(), "{source:?}: {diagnostics:?}");
        }
    }

    /// The arms of the first `match` in `let x = match ... { ... }`.
    fn arms(patterns: &str) -> Vec<super::ast::MatchArm> {
        let source = format!("let r = match subject {{\n{patterns}\n}}\n");
        let (program, diagnostics) = parse_program(&source);
        assert!(diagnostics.is_empty(), "{patterns:?}: {diagnostics:?}");
        let Item::Let(declaration) = &program.ast.items[0] else {
            panic!("let");
        };
        let ExprKind::Match { arms, .. } = &declaration.value.value else {
            panic!("match");
        };
        arms.clone()
    }

    fn pattern(source: &str) -> PatternKind {
        arms(&format!("{source} => 1"))[0].pattern.value.clone()
    }

    #[test]
    fn literal_patterns_cover_every_literal_the_language_has() {
        for (source, expected) in [
            ("1", ExprKind::Integer(1)),
            ("-1", ExprKind::Integer(-1)),
            ("\"a\"", ExprKind::Text("a".to_owned())),
            ("true", ExprKind::Bool(true)),
            ("false", ExprKind::Bool(false)),
            ("none", ExprKind::None),
            ("1.5", ExprKind::Decimal("1.5".to_owned())),
            ("-2.5", ExprKind::Decimal("-2.5".to_owned())),
            (
                "5s",
                ExprKind::Duration {
                    value: 5,
                    unit: "s".to_owned(),
                },
            ),
            ("50%", ExprKind::Percentage(50)),
        ] {
            assert_eq!(pattern(source), PatternKind::Literal(expected), "{source}");
        }
    }

    #[test]
    fn record_patterns_take_shorthand_and_nested_fields() {
        let PatternKind::Record { name, fields } = pattern("Note { author, content: c }") else {
            panic!("record")
        };
        assert_eq!(name, "Note");
        assert_eq!(
            fields[0],
            ("author".to_owned(), None),
            "shorthand binds the field"
        );
        assert_eq!(fields[1].0, "content");
        assert_eq!(
            fields[1].1.as_ref().unwrap().value,
            PatternKind::Binding("c".to_owned())
        );
        // Empty, trailing comma, and one field per line.
        assert_eq!(
            pattern("Note {}"),
            PatternKind::Record {
                name: "Note".to_owned(),
                fields: vec![]
            }
        );
        let PatternKind::Record { fields, .. } = pattern("Note { author, }") else {
            panic!("record")
        };
        assert_eq!(fields.len(), 1);
        let PatternKind::Record { fields, .. } = pattern("Note {\n    author,\n    content\n}")
        else {
            panic!("record")
        };
        assert_eq!(fields.len(), 2);
        // A field can hold any pattern, including a literal or a variant.
        let PatternKind::Record { fields, .. } = pattern("Note { kind: 1, author: Ok(a) }") else {
            panic!("record")
        };
        assert!(matches!(
            fields[0].1.as_ref().unwrap().value,
            PatternKind::Literal(_)
        ));
        assert!(matches!(
            fields[1].1.as_ref().unwrap().value,
            PatternKind::Variant { .. }
        ));
    }

    #[test]
    fn guards_parse_up_to_the_arrow_and_may_use_any_condition() {
        let guarded = arms("x if x > 5 => 1\ny if y > 1 and y < 4 => 2\n_ => 3");
        assert!(
            guarded[0].guard.is_some() && guarded[1].guard.is_some() && guarded[2].guard.is_none()
        );
        assert!(
            matches!(guarded[0].guard.as_ref().unwrap().value, ExprKind::Binary { ref operator, .. } if operator == ">")
        );
        assert!(
            matches!(guarded[1].guard.as_ref().unwrap().value, ExprKind::Binary { ref operator, .. } if operator == "and")
        );
        // The arrow was not read as part of the guard: each arm has its value.
        assert!(matches!(guarded[0].value.value, ExprKind::Integer(1)));
        // A guard on a record or variant pattern.
        let arms = arms("Ok(v) if v == 3 => 1\nNote { author } if author == \"a\" => 2");
        assert!(arms.iter().all(|arm| arm.guard.is_some()));
    }

    #[test]
    fn bindings_wildcards_and_variants_are_unchanged_and_capitalised_bare_names_are_unit_variants()
    {
        assert_eq!(pattern("x"), PatternKind::Binding("x".to_owned()));
        assert_eq!(pattern("_"), PatternKind::Wildcard);
        assert!(
            matches!(pattern("Ok(v)"), PatternKind::Variant { ref name, ref values } if name == "Ok" && values.len() == 1)
        );
        assert!(matches!(pattern("Ok(Err(e))"), PatternKind::Variant { .. }));
        // `None` used to parse as a binding, silently matching everything.
        assert_eq!(
            pattern("None"),
            PatternKind::Variant {
                name: "None".to_owned(),
                values: vec![]
            }
        );
        assert!(
            matches!(pattern("Ok(1)"), PatternKind::Variant { ref values, .. } if matches!(values[0].value, PatternKind::Literal(_)))
        );
    }

    #[test]
    fn malformed_patterns_are_errors_not_silent() {
        for source in [
            "let r = match s {\nNote { author, => 1\n}\n", // unclosed record pattern
            "let r = match s {\n- x => 1\n}\n",            // only a number can be negated
            "let r = match s {\n- \"a\" => 1\n}\n",
            "let r = match s {\nx if => 1\n}\n", // a guard needs a condition
            "let r = match s {\n1 => \n}\n",     // an arm needs a value
        ] {
            let (_, diagnostics) = parse_program(source);
            assert!(!diagnostics.is_empty(), "{source:?} was accepted");
        }
    }

    #[test]
    fn a_newline_ends_an_arms_value_so_a_negative_literal_starts_the_next_arm() {
        // `print("one")` then `-3 => ..` used to parse as `print("one") - 3`.
        let parsed = arms("1 => print(\"one\")\n-3 => print(\"neg\")\n_ => print(\"other\")");
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[1].pattern.value,
            PatternKind::Literal(ExprKind::Integer(-3))
        );
        assert!(matches!(parsed[0].value.value, ExprKind::Call { .. }));
    }

    #[test]
    fn brackets_inside_an_arm_may_still_span_lines() {
        let parsed = arms(
            "Ok(v) => print(\n    \"a\",\n    v + 1\n)\nErr(e) => [\n    1,\n    2\n]\n_ => (1\n + 2)",
        );
        assert_eq!(parsed.len(), 3);
        assert!(
            matches!(&parsed[0].value.value, ExprKind::Call { arguments, .. } if arguments.len() == 2)
        );
        assert!(matches!(&parsed[1].value.value, ExprKind::List(items) if items.len() == 2));
        assert!(
            matches!(&parsed[2].value.value, ExprKind::Binary { operator, .. } if operator == "+")
        );
    }

    #[test]
    fn a_continuation_line_that_starts_with_an_operator_is_an_error_not_a_silent_join() {
        // The arm ended at its line, so `+ 2` cannot continue it.
        let (_, diagnostics) = parse_program("let r = match s {\n_ => 1\n + 2\n}\n");
        assert!(!diagnostics.is_empty());
    }

    #[test]
    fn newlines_still_continue_expressions_outside_match_arms() {
        // The rule is scoped to arm values; ordinary expressions are unchanged.
        let (program, diagnostics) = parse_program("let total = 1\n    + 2\n    + 3\n");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let Item::Let(declaration) = &program.ast.items[0] else {
            panic!("let")
        };
        assert!(
            matches!(&declaration.value.value, ExprKind::Binary { operator, .. } if operator == "+")
        );
    }

    #[test]
    fn a_key_declaration_names_a_host_label() {
        let (program, diagnostics) = parse_program("key room = host(\"general\")\n");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(matches!(&program.ast.items[0], Item::Key(k) if k.name.value == "room"));
        for bad in [
            "key room = 1\n",
            "key room = host(1)\n",
            "key room = other(\"x\")\n",
        ] {
            assert!(
                parse_program(bad).1.iter().any(|d| d.code == "E1101"),
                "{bad}"
            );
        }
    }

    #[test]
    fn else_if_parses_as_a_nested_if_in_the_else_body() {
        // `spec/grammar.ebnf`'s `if_stmt` allows `"else", (block | if_stmt)`;
        // this was previously unimplemented — `else` only ever parsed a
        // literal block, so `else if` failed with "expected `{`".
        let (program, diagnostics) = parse_program(
            "on Note {\n    if x == 1 {\n        print(1)\n    } else if x == 2 {\n        print(2)\n    } else {\n        print(3)\n    }\n}\n",
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let Item::Statement(outer) = &program.ast.items[0] else {
            panic!("on statement")
        };
        let StatementKind::On { body, .. } = &outer.value else {
            panic!("on")
        };
        let Item::Statement(if_statement) = &body[0] else {
            panic!("if statement")
        };
        let StatementKind::If { else_body, .. } = &if_statement.value else {
            panic!("if")
        };
        // The `else if` is a single nested `if` statement, not two arms
        // flattened into one block.
        assert_eq!(else_body.len(), 1);
        let Item::Statement(nested) = &else_body[0] else {
            panic!("nested if wrapped as a statement")
        };
        let StatementKind::If {
            then_body: nested_then,
            else_body: nested_else,
            ..
        } = &nested.value
        else {
            panic!("else if nests another if, not a block")
        };
        assert_eq!(nested_then.len(), 1);
        // The trailing plain `else` is that nested `if`'s own else block, a
        // literal block again (not a further nested `if`).
        assert_eq!(nested_else.len(), 1);
        assert!(matches!(&nested_else[0], Item::Statement(_)));
    }

}
