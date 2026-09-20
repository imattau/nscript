//! Parsing, validation, and canonical hashing for declarative `NScript` modules.

use std::collections::{BTreeMap, BTreeSet};

use nscript_syntax::{Diagnostic, Span, Token, TokenKind, lex};
use semver::{Version, VersionReq};
use sha2::{Digest, Sha256};

mod resolver;

pub use resolver::{
    DiscoveryError, ModuleOrigin, ModuleRegistry, RegisteredModule, ResolutionError,
    ResolvedModuleGraph,
};

pub const CANONICAL_ENCODING_VERSION: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleId {
    pub name: String,
    pub version: Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleDescriptor {
    pub id: ModuleId,
    pub language: VersionReq,
    pub reference: Option<String>,
    pub dependencies: Vec<ModuleDependency>,
    pub events: Vec<EventDefinition>,
    pub tags: Vec<TagDefinition>,
    pub canonical_encoding: u8,
    pub canonical_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleDependency {
    pub name: String,
    pub requirement: VersionReq,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EventMode {
    Regular,
    Replaceable,
    Addressable,
    Ephemeral,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDefinition {
    pub name: String,
    pub kind: u16,
    pub mode: EventMode,
    pub content_type: String,
    pub content_encoding: Option<String>,
    pub tags_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagDefinition {
    pub name: String,
    pub wire_name: String,
    pub slots: Vec<TagSlot>,
    pub validators: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TagSlot {
    Field {
        name: String,
        type_name: String,
        position: u16,
    },
    Literal {
        value: String,
        position: u16,
    },
}

impl TagSlot {
    fn position(&self) -> u16 {
        match self {
            Self::Field { position, .. } | Self::Literal { position, .. } => *position,
        }
    }
}

#[must_use]
pub fn parse_module(source: &str) -> (Option<ModuleDescriptor>, Vec<Diagnostic>) {
    let mut parser = Parser::new(lex(source));
    let descriptor = parser.parse();
    if parser.diagnostics.is_empty() {
        (descriptor, parser.diagnostics)
    } else {
        (None, parser.diagnostics)
    }
}

#[must_use]
pub fn hash_hex(hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    hash.iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        })
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
    diagnostics: Vec<Diagnostic>,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            index: 0,
            diagnostics: Vec::new(),
        }
    }

    fn parse(&mut self) -> Option<ModuleDescriptor> {
        self.skip_terminators();
        self.expect_keyword("module")?;
        let (name, _) = self.take_identifier()?;
        self.expect_symbol('@')?;
        let version = self.take_version()?;
        self.skip_to_next_line();

        self.expect_keyword("language")?;
        let (language_text, language_span) = self.take_string()?;
        let normalized_language = language_text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(", ");
        let language = match VersionReq::parse(&normalized_language) {
            Ok(requirement) => requirement,
            Err(error) => {
                self.error(
                    language_span,
                    format!("invalid language version range: {error}"),
                );
                return None;
            }
        };
        self.skip_to_next_line();

        self.skip_terminators();
        let reference = if self.at_keyword("reference") {
            self.index += 1;
            let value = self.take_string().map(|(value, _)| value);
            self.skip_to_next_line();
            value
        } else {
            None
        };

        let mut events = Vec::new();
        let mut tags = Vec::new();
        let mut dependencies = Vec::new();
        self.skip_terminators();
        while !self.is_at_end() {
            if self.at_keyword("use") {
                if let Some(dependency) = self.parse_dependency() {
                    dependencies.push(dependency);
                }
            } else if self.at_keyword("event") {
                if let Some(event) = self.parse_event() {
                    events.push(event);
                }
            } else if self.at_keyword("tag") {
                if let Some(tag) = self.parse_tag() {
                    tags.push(tag);
                }
            } else {
                let span = self.current_span();
                self.error(span, "unsupported or malformed module item");
                self.skip_item();
            }
            self.skip_terminators();
        }

        validate_unique_names(&events, &tags, &mut self.diagnostics);
        dependencies.sort_by(|left, right| left.name.cmp(&right.name));
        for pair in dependencies.windows(2) {
            if pair[0].name == pair[1].name {
                self.error(
                    Span::default(),
                    format!("duplicate dependency `{}`", pair[0].name),
                );
            }
        }
        let id = ModuleId { name, version };
        let mut descriptor = ModuleDescriptor {
            id,
            language,
            reference,
            dependencies,
            events,
            tags,
            canonical_encoding: CANONICAL_ENCODING_VERSION,
            canonical_hash: [0; 32],
        };
        descriptor.canonical_hash = canonical_hash(&descriptor);
        Some(descriptor)
    }

    fn parse_dependency(&mut self) -> Option<ModuleDependency> {
        self.expect_keyword("use")?;
        let name = self.take_module_path()?;
        self.expect_symbol('@')?;
        let requirement = if let Some(Token {
            kind: TokenKind::String(value),
            span,
        }) = self.tokens.get(self.index).cloned()
        {
            self.index += 1;
            self.parse_version_requirement(&value, span)?
        } else {
            let version = self.take_version()?;
            VersionReq::parse(&format!("={version}"))
                .expect("an exact Version is a valid VersionReq")
        };
        self.skip_to_next_line();
        Some(ModuleDependency { name, requirement })
    }

    fn take_module_path(&mut self) -> Option<String> {
        let (first, _) = self.take_identifier()?;
        let mut path = first;
        while self.at_symbol(':')
            && matches!(
                self.tokens.get(self.index + 1).map(|token| &token.kind),
                Some(TokenKind::Symbol(':'))
            )
        {
            self.index += 2;
            let (segment, _) = self.take_identifier()?;
            path.push_str("::");
            path.push_str(&segment);
        }
        Some(path)
    }

    fn parse_version_requirement(&mut self, value: &str, span: Span) -> Option<VersionReq> {
        let normalized = value.split_whitespace().collect::<Vec<_>>().join(", ");
        match VersionReq::parse(&normalized) {
            Ok(requirement) => Some(requirement),
            Err(error) => {
                self.error(span, format!("invalid version requirement: {error}"));
                None
            }
        }
    }

    fn parse_event(&mut self) -> Option<EventDefinition> {
        self.expect_keyword("event")?;
        let (name, name_span) = self.take_identifier()?;
        self.expect_symbol('{')?;
        self.skip_terminators();

        let mut kind = None;
        let mut mode = None;
        let mut content_type = None;
        let mut content_encoding = None;
        let mut tags_type = None;
        while !self.at_symbol('}') && !self.is_at_end() {
            let Some((key, key_span)) = self.take_identifier() else {
                self.skip_to_next_line();
                continue;
            };
            self.expect_symbol(':');
            match key.as_str() {
                "kind" => {
                    kind = self.take_u16();
                }
                "mode" => {
                    mode = self.take_identifier().and_then(|(value, span)| {
                        parse_event_mode(&value).or_else(|| {
                            self.error(span, format!("invalid event mode `{value}`"));
                            None
                        })
                    });
                }
                "content" => {
                    content_type = self.take_type_name();
                    if self.at_keyword("as") {
                        self.index += 1;
                        content_encoding = self.take_type_name();
                    }
                }
                "tags" => {
                    tags_type = self.take_type_name();
                }
                _ => self.error(key_span, format!("unknown event property `{key}`")),
            }
            self.skip_to_next_line_or('}');
            self.skip_terminators();
        }
        self.expect_symbol('}');

        let Some(kind) = kind else {
            self.error(name_span, "event is missing `kind`");
            return None;
        };
        let Some(mode) = mode else {
            self.error(name_span, "event is missing `mode`");
            return None;
        };
        let Some(content_type) = content_type else {
            self.error(name_span, "event is missing `content`");
            return None;
        };
        Some(EventDefinition {
            name,
            kind,
            mode,
            content_type,
            content_encoding,
            tags_type,
        })
    }

    fn parse_tag(&mut self) -> Option<TagDefinition> {
        self.expect_keyword("tag")?;
        let (name, name_span) = self.take_identifier()?;
        self.expect_symbol('{')?;
        self.skip_terminators();

        let mut wire_name = None;
        let mut slots = Vec::new();
        let mut validators = Vec::new();
        while !self.at_symbol('}') && !self.is_at_end() {
            if self.at_keyword("wire") {
                let wire_span = self.current_span();
                self.index += 1;
                self.expect_symbol(':');
                match self.take_string() {
                    Some((value, _)) => wire_name = Some(value),
                    None => self.error(wire_span, "wire name must be a string literal"),
                }
            } else if self.at_keyword("field") {
                self.index += 1;
                let (field_name, _) = self.take_identifier()?;
                self.expect_symbol(':');
                let type_name = self.take_type_name()?;
                self.expect_keyword("at");
                let position = self.take_u16()?;
                slots.push(TagSlot::Field {
                    name: field_name,
                    type_name,
                    position,
                });
            } else if self.at_keyword("literal") {
                self.index += 1;
                let (value, _) = self.take_string()?;
                self.expect_keyword("at");
                let position = self.take_u16()?;
                slots.push(TagSlot::Literal { value, position });
            } else if self.at_keyword("require") {
                self.index += 1;
                validators.push(self.take_line_text());
            } else {
                let span = self.current_span();
                self.error(span, "unknown tag property");
            }
            self.skip_to_next_line_or('}');
            self.skip_terminators();
        }
        self.expect_symbol('}');

        let Some(wire_name) = wire_name else {
            self.error(name_span, "tag is missing a literal `wire` name");
            return None;
        };
        let mut positions = BTreeSet::new();
        for slot in &slots {
            if !positions.insert(slot.position()) {
                self.error(
                    name_span,
                    format!("duplicate tag position {}", slot.position()),
                );
            }
        }
        slots.sort_by_key(TagSlot::position);
        Some(TagDefinition {
            name,
            wire_name,
            slots,
            validators,
        })
    }

    fn take_version(&mut self) -> Option<Version> {
        let start = self.current_span();
        let mut text = String::new();
        while let Some(token) = self.tokens.get(self.index) {
            match &token.kind {
                TokenKind::Number(value) | TokenKind::Identifier(value) => {
                    text.push_str(value);
                }
                TokenKind::Symbol(value @ ('.' | '-' | '+')) => text.push(*value),
                _ => break,
            }
            self.index += 1;
        }
        match Version::parse(&text) {
            Ok(version) => Some(version),
            Err(error) => {
                self.error(start, format!("invalid module version `{text}`: {error}"));
                None
            }
        }
    }

    fn take_type_name(&mut self) -> Option<String> {
        let (base, _) = self.take_identifier()?;
        let mut output = base;
        if self.at_symbol('<') {
            output.push('<');
            self.index += 1;
            let mut depth = 1_u32;
            while !self.is_at_end() && depth > 0 {
                match &self.tokens[self.index].kind {
                    TokenKind::Identifier(value) | TokenKind::Number(value) => {
                        output.push_str(value);
                    }
                    TokenKind::Symbol('<') => {
                        depth += 1;
                        output.push('<');
                    }
                    TokenKind::Symbol('>') => {
                        depth -= 1;
                        output.push('>');
                    }
                    TokenKind::Symbol(',') => output.push(','),
                    _ => break,
                }
                self.index += 1;
            }
        }
        Some(output)
    }

    fn take_line_text(&mut self) -> String {
        let mut output = String::new();
        while let Some(token) = self.tokens.get(self.index) {
            match &token.kind {
                TokenKind::Newline | TokenKind::Symbol(';' | '}') => break,
                TokenKind::Identifier(value) | TokenKind::Number(value) => output.push_str(value),
                TokenKind::String(value) => {
                    output.push('"');
                    output.push_str(value);
                    output.push('"');
                }
                TokenKind::Symbol(value) => output.push(*value),
            }
            self.index += 1;
        }
        output
    }

    fn take_u16(&mut self) -> Option<u16> {
        let token = self.tokens.get(self.index)?.clone();
        let TokenKind::Number(text) = token.kind else {
            self.error(token.span, "expected an unsigned 16-bit integer");
            return None;
        };
        self.index += 1;
        match text.replace('_', "").parse() {
            Ok(value) => Some(value),
            Err(error) => {
                self.error(
                    token.span,
                    format!("invalid unsigned 16-bit integer: {error}"),
                );
                None
            }
        }
    }

    fn take_identifier(&mut self) -> Option<(String, Span)> {
        let token = self.tokens.get(self.index)?.clone();
        let TokenKind::Identifier(value) = token.kind else {
            self.error(token.span, "expected an identifier");
            return None;
        };
        self.index += 1;
        Some((value, token.span))
    }

    fn take_string(&mut self) -> Option<(String, Span)> {
        let token = self.tokens.get(self.index)?.clone();
        let TokenKind::String(value) = token.kind else {
            self.error(token.span, "expected a string literal");
            return None;
        };
        self.index += 1;
        Some((value, token.span))
    }

    fn expect_keyword(&mut self, expected: &str) -> Option<()> {
        let (actual, span) = self.take_identifier()?;
        if actual == expected {
            Some(())
        } else {
            self.error(span, format!("expected `{expected}`, found `{actual}`"));
            None
        }
    }

    fn expect_symbol(&mut self, expected: char) -> Option<()> {
        let token = self.tokens.get(self.index)?.clone();
        if token.kind == TokenKind::Symbol(expected) {
            self.index += 1;
            Some(())
        } else {
            self.error(token.span, format!("expected `{expected}`"));
            None
        }
    }

    fn at_keyword(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.index).map(|token| &token.kind), Some(TokenKind::Identifier(value)) if value == expected)
    }

    fn at_symbol(&self, expected: char) -> bool {
        matches!(self.tokens.get(self.index).map(|token| &token.kind), Some(TokenKind::Symbol(value)) if *value == expected)
    }

    fn skip_terminators(&mut self) {
        while matches!(
            self.tokens.get(self.index).map(|token| &token.kind),
            Some(TokenKind::Newline | TokenKind::Symbol(';'))
        ) {
            self.index += 1;
        }
    }

    fn skip_to_next_line(&mut self) {
        while !matches!(
            self.tokens.get(self.index).map(|token| &token.kind),
            None | Some(TokenKind::Newline)
        ) {
            self.index += 1;
        }
        self.skip_terminators();
    }

    fn skip_to_next_line_or(&mut self, symbol: char) {
        while !matches!(
            self.tokens.get(self.index).map(|token| &token.kind),
            None | Some(TokenKind::Newline)
        ) && !self.at_symbol(symbol)
        {
            self.index += 1;
        }
    }

    fn skip_item(&mut self) {
        let mut depth = 0_i32;
        while let Some(token) = self.tokens.get(self.index) {
            match token.kind {
                TokenKind::Symbol('{') => depth += 1,
                TokenKind::Symbol('}') if depth > 0 => depth -= 1,
                TokenKind::Newline if depth == 0 => {
                    self.index += 1;
                    break;
                }
                _ => {}
            }
            self.index += 1;
        }
    }

    fn current_span(&self) -> Span {
        self.tokens
            .get(self.index)
            .map_or(Span::default(), |token| token.span)
    }

    fn is_at_end(&self) -> bool {
        self.index >= self.tokens.len()
    }

    fn error(&mut self, span: Span, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            code: "E4003",
            message: message.into(),
            span,
        });
    }
}

fn parse_event_mode(value: &str) -> Option<EventMode> {
    match value {
        "regular" => Some(EventMode::Regular),
        "replaceable" => Some(EventMode::Replaceable),
        "addressable" => Some(EventMode::Addressable),
        "ephemeral" => Some(EventMode::Ephemeral),
        _ => None,
    }
}

fn validate_unique_names(
    events: &[EventDefinition],
    tags: &[TagDefinition],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut names = BTreeSet::new();
    for name in events
        .iter()
        .map(|event| &event.name)
        .chain(tags.iter().map(|tag| &tag.name))
    {
        if !names.insert(name) {
            diagnostics.push(Diagnostic {
                code: "E4003",
                message: format!("duplicate module export `{name}`"),
                span: Span::default(),
            });
        }
    }
}

fn canonical_hash(descriptor: &ModuleDescriptor) -> [u8; 32] {
    let mut fields = BTreeMap::new();
    fields.insert("language", descriptor.language.to_string());
    fields.insert("module", descriptor.id.name.clone());
    fields.insert("version", descriptor.id.version.to_string());
    if let Some(reference) = &descriptor.reference {
        fields.insert("reference", reference.clone());
    }

    let mut canonical = Vec::from(b"NSM\0".as_slice());
    canonical.push(descriptor.canonical_encoding);
    encode_count(&mut canonical, fields.len());
    for (key, value) in fields {
        encode_string(&mut canonical, key);
        encode_string(&mut canonical, &value);
    }
    let mut dependencies = descriptor.dependencies.iter().collect::<Vec<_>>();
    dependencies.sort_by(|left, right| left.name.cmp(&right.name));
    encode_count(&mut canonical, dependencies.len());
    for dependency in dependencies {
        encode_string(&mut canonical, &dependency.name);
        encode_string(&mut canonical, &dependency.requirement.to_string());
    }
    let mut events = descriptor.events.iter().collect::<Vec<_>>();
    events.sort_by_key(|event| &event.name);
    encode_count(&mut canonical, events.len());
    for event in events {
        encode_string(&mut canonical, &event.name);
        canonical.extend_from_slice(&event.kind.to_be_bytes());
        canonical.push(match event.mode {
            EventMode::Regular => 0,
            EventMode::Replaceable => 1,
            EventMode::Addressable => 2,
            EventMode::Ephemeral => 3,
        });
        encode_string(&mut canonical, &event.content_type);
        encode_option(&mut canonical, event.content_encoding.as_deref());
        encode_option(&mut canonical, event.tags_type.as_deref());
    }
    let mut tags = descriptor.tags.iter().collect::<Vec<_>>();
    tags.sort_by_key(|tag| &tag.name);
    encode_count(&mut canonical, tags.len());
    for tag in tags {
        encode_string(&mut canonical, &tag.name);
        encode_string(&mut canonical, &tag.wire_name);
        encode_count(&mut canonical, tag.slots.len());
        for slot in &tag.slots {
            match slot {
                TagSlot::Field {
                    name,
                    type_name,
                    position,
                } => {
                    canonical.push(0);
                    canonical.extend_from_slice(&position.to_be_bytes());
                    encode_string(&mut canonical, name);
                    encode_string(&mut canonical, type_name);
                }
                TagSlot::Literal { value, position } => {
                    canonical.push(1);
                    canonical.extend_from_slice(&position.to_be_bytes());
                    encode_string(&mut canonical, value);
                }
            }
        }
        let mut validators = tag.validators.iter().collect::<Vec<_>>();
        validators.sort();
        encode_count(&mut canonical, validators.len());
        for validator in validators {
            encode_string(&mut canonical, validator);
        }
    }
    Sha256::digest(canonical).into()
}

fn encode_option(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            encode_string(output, value);
        }
        None => output.push(0),
    }
}

fn encode_string(output: &mut Vec<u8>, value: &str) {
    let length = u32::try_from(value.len()).expect("module field exceeds u32::MAX bytes");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn encode_count(output: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("module collection exceeds u32::MAX items");
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::{hash_hex, parse_module};

    const NIP10: &str = include_str!("../../../conformance/modules/valid/nip10.nsm");

    #[test]
    fn parses_nip10_descriptor() {
        let (descriptor, diagnostics) = parse_module(NIP10);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let descriptor = descriptor.expect("valid descriptor");
        assert_eq!(descriptor.id.name, "nip10");
        assert_eq!(descriptor.events[0].kind, 1);
        assert_eq!(descriptor.tags[0].wire_name, "e");
        assert_eq!(
            hash_hex(&descriptor.canonical_hash),
            "db363e34d76b43e879abda58eddb7debbec104fba643c755906e44647451895f"
        );
    }

    #[test]
    fn comments_do_not_change_descriptor_hash() {
        let (first, first_diagnostics) = parse_module(NIP10);
        let decorated = format!("// leading comment\n\n{NIP10}\n// trailing comment\n");
        let (second, second_diagnostics) = parse_module(&decorated);
        assert!(first_diagnostics.is_empty());
        assert!(second_diagnostics.is_empty());
        assert_eq!(
            first.unwrap().canonical_hash,
            second.unwrap().canonical_hash
        );
    }

    #[test]
    fn rejects_dynamic_wire_name() {
        let source = include_str!("../../../conformance/modules/invalid/dynamic-wire-name.nsm");
        let (descriptor, diagnostics) = parse_module(source);
        assert!(descriptor.is_none());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "E4003")
        );
    }
}
