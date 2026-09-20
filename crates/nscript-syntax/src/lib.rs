//! Lexical and structural parsing for `NScript` source files.

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
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

#[derive(Clone, Debug, Default)]
pub struct Program {
    pub profile: RuntimeProfile,
    pub profile_span: Option<Span>,
    pub defaults: Defaults,
    pub signers: BTreeSet<String>,
    pub relaysets: BTreeSet<String>,
    pub identifiers: Vec<(String, Span)>,
    pub publishes: Vec<PublishSite>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
    pub span: Span,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn lex(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let (mut offset, mut line, mut column) = (0, 1, 1);

    while offset < bytes.len() {
        let start = offset;
        let start_column = column;
        match bytes[offset] {
            b' ' | b'\t' | b'\r' => {
                offset += 1;
                column += 1;
            }
            b'\n' => {
                tokens.push(Token {
                    kind: TokenKind::Newline,
                    span: Span {
                        start,
                        end: start + 1,
                        line,
                        column,
                    },
                });
                offset += 1;
                line += 1;
                column = 1;
            }
            b'/' if bytes.get(offset + 1) == Some(&b'/') => {
                while offset < bytes.len() && bytes[offset] != b'\n' {
                    offset += 1;
                    column += 1;
                }
            }
            b'"' => {
                offset += 1;
                column += 1;
                let value_start = offset;
                while offset < bytes.len() && bytes[offset] != b'"' {
                    if bytes[offset] == b'\\' && offset + 1 < bytes.len() {
                        offset += 2;
                        column += 2;
                    } else {
                        offset += 1;
                        column += 1;
                    }
                }
                let value = source[value_start..offset].to_owned();
                if offset < bytes.len() {
                    offset += 1;
                    column += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::String(value),
                    span: Span {
                        start,
                        end: offset,
                        line,
                        column: start_column,
                    },
                });
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                offset += 1;
                column += 1;
                while offset < bytes.len()
                    && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
                {
                    offset += 1;
                    column += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Identifier(source[start..offset].to_owned()),
                    span: Span {
                        start,
                        end: offset,
                        line,
                        column: start_column,
                    },
                });
            }
            byte if byte.is_ascii_digit() => {
                offset += 1;
                column += 1;
                while offset < bytes.len()
                    && (bytes[offset].is_ascii_digit() || bytes[offset] == b'_')
                {
                    offset += 1;
                    column += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Number(source[start..offset].to_owned()),
                    span: Span {
                        start,
                        end: offset,
                        line,
                        column: start_column,
                    },
                });
            }
            symbol => {
                offset += 1;
                column += 1;
                tokens.push(Token {
                    kind: TokenKind::Symbol(char::from(symbol)),
                    span: Span {
                        start,
                        end: offset,
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
    let mut program = Program::default();
    let mut diagnostics = Vec::new();
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
    use super::{RuntimeProfile, parse_program};

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
}
