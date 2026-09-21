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
    use super::ast::{ExprKind, Item, StatementKind};
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
}
