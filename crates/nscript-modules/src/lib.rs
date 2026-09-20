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
    pub types: Vec<TypeDefinition>,
    pub validators: Vec<ValidatorDefinition>,
    pub events: Vec<EventDefinition>,
    pub tags: Vec<TagDefinition>,
    pub operations: Vec<HostOperation>,
    pub errors: Vec<ErrorDefinition>,
    pub vectors: Vec<TestVector>,
    pub canonical_encoding: u8,
    pub canonical_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleDependency {
    pub name: String,
    pub requirement: VersionReq,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypeDefinition {
    Nominal {
        name: String,
        base: String,
        requirements: Vec<String>,
    },
    Record {
        name: String,
        fields: Vec<SchemaField>,
    },
    Enum {
        name: String,
        variants: Vec<String>,
    },
}

impl TypeDefinition {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Nominal { name, .. } | Self::Record { name, .. } | Self::Enum { name, .. } => {
                name
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaField {
    pub name: String,
    pub type_name: String,
    pub default: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorDefinition {
    pub name: String,
    pub parameters: Vec<SchemaField>,
    pub requirements: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOperation {
    pub name: String,
    pub parameters: Vec<SchemaField>,
    pub return_type: String,
    pub effects: Vec<String>,
    pub permission: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorDefinition {
    pub name: String,
    pub fields: Vec<SchemaField>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestVector {
    pub name: String,
    pub value: String,
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
    pub fields: Vec<SchemaField>,
    pub requirements: Vec<String>,
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

#[derive(Default)]
struct ModuleItems {
    dependencies: Vec<ModuleDependency>,
    types: Vec<TypeDefinition>,
    validators: Vec<ValidatorDefinition>,
    events: Vec<EventDefinition>,
    tags: Vec<TagDefinition>,
    operations: Vec<HostOperation>,
    errors: Vec<ErrorDefinition>,
    vectors: Vec<TestVector>,
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
        let name = self.take_module_path()?;
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

        let mut items = self.parse_items();
        validate_unique_names(
            &items.types,
            &items.validators,
            &items.events,
            &items.tags,
            &items.operations,
            &items.errors,
            &mut self.diagnostics,
        );
        validate_validator_graph(&items.validators, &mut self.diagnostics);
        items
            .dependencies
            .sort_by(|left, right| left.name.cmp(&right.name));
        for pair in items.dependencies.windows(2) {
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
            dependencies: items.dependencies,
            types: items.types,
            validators: items.validators,
            events: items.events,
            tags: items.tags,
            operations: items.operations,
            errors: items.errors,
            vectors: items.vectors,
            canonical_encoding: CANONICAL_ENCODING_VERSION,
            canonical_hash: [0; 32],
        };
        descriptor.canonical_hash = canonical_hash(&descriptor);
        Some(descriptor)
    }

    fn parse_items(&mut self) -> ModuleItems {
        let mut items = ModuleItems::default();
        self.skip_terminators();
        while !self.is_at_end() {
            if self.at_keyword("use") {
                if let Some(dependency) = self.parse_dependency() {
                    items.dependencies.push(dependency);
                }
            } else if self.at_keyword("nominal") {
                if let Some(item) = self.parse_nominal() {
                    items.types.push(item);
                }
            } else if self.at_keyword("record") {
                if let Some(item) = self.parse_record() {
                    items.types.push(item);
                }
            } else if self.at_keyword("enum") {
                if let Some(item) = self.parse_enum() {
                    items.types.push(item);
                }
            } else if self.at_keyword("validator") {
                if let Some(item) = self.parse_validator() {
                    items.validators.push(item);
                }
            } else if self.at_keyword("event") {
                if let Some(event) = self.parse_event() {
                    items.events.push(event);
                }
            } else if self.at_keyword("tag") {
                if let Some(tag) = self.parse_tag() {
                    items.tags.push(tag);
                }
            } else if self.at_keyword("operation") {
                if let Some(item) = self.parse_operation() {
                    items.operations.push(item);
                }
            } else if self.at_keyword("error") {
                if let Some(item) = self.parse_error() {
                    items.errors.push(item);
                }
            } else if self.at_keyword("vector") {
                if let Some(item) = self.parse_vector() {
                    items.vectors.push(item);
                }
            } else {
                let span = self.current_span();
                self.error(span, "unsupported or malformed module item");
                self.skip_item();
            }
            self.skip_terminators();
        }
        items
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

    fn parse_nominal(&mut self) -> Option<TypeDefinition> {
        self.expect_keyword("nominal")?;
        let (name, _) = self.take_identifier()?;
        self.expect_keyword("from")?;
        let base = self.take_type_name()?;
        self.expect_symbol('{')?;
        let requirements = self.parse_requirements();
        self.expect_symbol('}')?;
        Some(TypeDefinition::Nominal {
            name,
            base,
            requirements,
        })
    }

    fn parse_record(&mut self) -> Option<TypeDefinition> {
        self.expect_keyword("record")?;
        let (name, span) = self.take_identifier()?;
        let fields = self.parse_schema_fields()?;
        validate_fields(&name, span, &fields, &mut self.diagnostics);
        Some(TypeDefinition::Record { name, fields })
    }

    fn parse_enum(&mut self) -> Option<TypeDefinition> {
        self.expect_keyword("enum")?;
        let (name, span) = self.take_identifier()?;
        self.expect_symbol('{')?;
        self.skip_terminators();
        let mut variants = Vec::new();
        while !self.at_symbol('}') && !self.is_at_end() {
            let (variant, _) = self.take_identifier()?;
            variants.push(variant);
            if self.at_symbol(',') {
                self.index += 1;
            }
            self.skip_terminators();
        }
        self.expect_symbol('}')?;
        if variants.is_empty() {
            self.error(span, format!("enum `{name}` must contain a variant"));
        }
        let mut unique = BTreeSet::new();
        for variant in &variants {
            if !unique.insert(variant) {
                self.error(span, format!("duplicate enum variant `{variant}`"));
            }
        }
        Some(TypeDefinition::Enum { name, variants })
    }

    fn parse_validator(&mut self) -> Option<ValidatorDefinition> {
        self.expect_keyword("validator")?;
        let (name, span) = self.take_identifier()?;
        let parameters = self.parse_parameters()?;
        validate_fields(&name, span, &parameters, &mut self.diagnostics);
        self.expect_symbol('{')?;
        let requirements = self.parse_requirements();
        self.expect_symbol('}')?;
        if requirements.is_empty() {
            self.error(span, format!("validator `{name}` has no requirements"));
        }
        Some(ValidatorDefinition {
            name,
            parameters,
            requirements,
        })
    }

    fn parse_operation(&mut self) -> Option<HostOperation> {
        self.expect_keyword("operation")?;
        let (name, span) = self.take_identifier()?;
        let parameters = self.parse_parameters()?;
        validate_fields(&name, span, &parameters, &mut self.diagnostics);
        self.expect_symbol('-')?;
        self.expect_symbol('>')?;
        let return_type = self.take_type_name()?;
        self.expect_keyword("effect")?;
        let mut effects = Vec::new();
        while !self.at_keyword("permission") && !self.is_at_end() {
            let (effect, _) = self.take_identifier()?;
            effects.push(effect);
            if self.at_symbol(',') {
                self.index += 1;
            }
        }
        self.expect_keyword("permission")?;
        let permission = self.take_line_text();
        if effects.is_empty() {
            self.error(span, format!("operation `{name}` must declare an effect"));
        }
        if permission.is_empty() {
            self.error(
                span,
                format!("operation `{name}` must declare a permission"),
            );
        }
        let allowed = [
            "Relay",
            "Sign",
            "Encrypt",
            "Decrypt",
            "Storage",
            "HTTP",
            "Filesystem",
            "Payment",
            "Clock",
            "Log",
        ];
        for effect in &effects {
            if !allowed.contains(&effect.as_str()) {
                self.error(span, format!("unknown effect `{effect}`"));
            }
        }
        effects.sort();
        effects.dedup();
        Some(HostOperation {
            name,
            parameters,
            return_type,
            effects,
            permission,
        })
    }

    fn parse_error(&mut self) -> Option<ErrorDefinition> {
        self.expect_keyword("error")?;
        let (name, span) = self.take_identifier()?;
        let fields = if self.at_symbol('{') {
            self.parse_schema_fields()?
        } else {
            self.skip_to_next_line();
            Vec::new()
        };
        validate_fields(&name, span, &fields, &mut self.diagnostics);
        Some(ErrorDefinition { name, fields })
    }

    fn parse_vector(&mut self) -> Option<TestVector> {
        self.expect_keyword("vector")?;
        let (name, _) = self.take_string()?;
        let value = self.take_balanced_record()?;
        self.skip_to_next_line();
        Some(TestVector { name, value })
    }

    fn parse_schema_fields(&mut self) -> Option<Vec<SchemaField>> {
        self.expect_symbol('{')?;
        self.skip_terminators();
        let mut fields = Vec::new();
        while !self.at_symbol('}') && !self.is_at_end() {
            self.expect_keyword("field")?;
            let (name, _) = self.take_identifier()?;
            self.expect_symbol(':')?;
            let type_name = self.take_type_name()?;
            let default = if self.at_symbol('=') {
                self.index += 1;
                Some(self.take_line_text())
            } else {
                None
            };
            fields.push(SchemaField {
                name,
                type_name,
                default,
            });
            self.skip_to_next_line_or('}');
            self.skip_terminators();
        }
        self.expect_symbol('}')?;
        Some(fields)
    }

    fn parse_parameters(&mut self) -> Option<Vec<SchemaField>> {
        self.expect_symbol('(')?;
        let mut parameters = Vec::new();
        while !self.at_symbol(')') && !self.is_at_end() {
            let (name, _) = self.take_identifier()?;
            self.expect_symbol(':')?;
            let type_name = self.take_type_name()?;
            parameters.push(SchemaField {
                name,
                type_name,
                default: None,
            });
            if self.at_symbol(',') {
                self.index += 1;
            }
        }
        self.expect_symbol(')')?;
        Some(parameters)
    }

    fn parse_requirements(&mut self) -> Vec<String> {
        self.skip_terminators();
        let mut requirements = Vec::new();
        while !self.at_symbol('}') && !self.is_at_end() {
            if self.at_keyword("require") {
                self.index += 1;
                requirements.push(self.take_line_text());
            } else {
                let span = self.current_span();
                self.error(span, "expected `require`");
                self.skip_to_next_line_or('}');
            }
            self.skip_terminators();
        }
        requirements
    }

    fn take_balanced_record(&mut self) -> Option<String> {
        self.expect_symbol('{')?;
        let mut output = String::from("{");
        let mut depth = 1_u32;
        while !self.is_at_end() && depth > 0 {
            match &self.tokens[self.index].kind {
                TokenKind::Symbol('{') => {
                    depth += 1;
                    output.push('{');
                }
                TokenKind::Symbol('}') => {
                    depth -= 1;
                    output.push('}');
                }
                TokenKind::Identifier(value) | TokenKind::Number(value) => output.push_str(value),
                TokenKind::String(value) => {
                    output.push('"');
                    output.push_str(value);
                    output.push('"');
                }
                TokenKind::Symbol(value) => output.push(*value),
                TokenKind::Newline => {}
            }
            self.index += 1;
        }
        (depth == 0).then_some(output)
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
        let mut fields = Vec::new();
        let mut requirements = Vec::new();
        while !self.at_symbol('}') && !self.is_at_end() {
            if self.at_keyword("field") {
                fields.push(self.parse_event_field()?);
                self.skip_to_next_line_or('}');
                self.skip_terminators();
                continue;
            }
            if self.at_keyword("require") {
                self.index += 1;
                requirements.push(self.take_line_text());
                self.skip_to_next_line_or('}');
                self.skip_terminators();
                continue;
            }
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
        if mode == EventMode::Addressable && tags_type.is_none() {
            self.error(
                name_span,
                "addressable event must declare a tag collection containing its identifier",
            );
        }
        validate_fields(&name, name_span, &fields, &mut self.diagnostics);
        Some(EventDefinition {
            name,
            kind,
            mode,
            content_type,
            content_encoding,
            tags_type,
            fields,
            requirements,
        })
    }

    fn parse_event_field(&mut self) -> Option<SchemaField> {
        self.expect_keyword("field")?;
        let (name, _) = self.take_identifier()?;
        self.expect_symbol(':')?;
        let type_name = self.take_type_name()?;
        let default = if self.at_symbol('=') {
            self.index += 1;
            Some(self.take_line_text())
        } else {
            None
        };
        Some(SchemaField {
            name,
            type_name,
            default,
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
        for (expected, slot) in (1_u16..).zip(&slots) {
            if slot.position() != expected {
                self.error(
                    name_span,
                    format!(
                        "tag positions must be contiguous from 1; expected {expected}, found {}",
                        slot.position()
                    ),
                );
                break;
            }
        }
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
    types: &[TypeDefinition],
    validators: &[ValidatorDefinition],
    events: &[EventDefinition],
    tags: &[TagDefinition],
    operations: &[HostOperation],
    errors: &[ErrorDefinition],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut names = BTreeSet::new();
    for name in types
        .iter()
        .map(TypeDefinition::name)
        .chain(validators.iter().map(|item| item.name.as_str()))
        .chain(events.iter().map(|event| event.name.as_str()))
        .chain(tags.iter().map(|tag| tag.name.as_str()))
        .chain(operations.iter().map(|item| item.name.as_str()))
        .chain(errors.iter().map(|item| item.name.as_str()))
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

fn validate_fields(
    owner: &str,
    span: Span,
    fields: &[SchemaField],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut names = BTreeSet::new();
    for field in fields {
        if !names.insert(&field.name) {
            diagnostics.push(Diagnostic {
                code: "E4003",
                message: format!("duplicate field `{}` in `{owner}`", field.name),
                span,
            });
        }
    }
}

fn validate_validator_graph(validators: &[ValidatorDefinition], diagnostics: &mut Vec<Diagnostic>) {
    let names = validators
        .iter()
        .map(|validator| validator.name.clone())
        .collect::<BTreeSet<_>>();
    let allowed = ["length", "matches", "contains"];
    let mut graph = BTreeMap::<String, BTreeSet<String>>::new();
    for validator in validators {
        let edges = graph.entry(validator.name.clone()).or_default();
        for requirement in &validator.requirements {
            let tokens = lex(requirement);
            for pair in tokens.windows(2) {
                if let [
                    Token {
                        kind: TokenKind::Identifier(function),
                        ..
                    },
                    Token {
                        kind: TokenKind::Symbol('('),
                        ..
                    },
                ] = pair
                {
                    if names.contains(function) {
                        edges.insert(function.clone());
                    } else if !allowed.contains(&function.as_str()) {
                        diagnostics.push(Diagnostic {
                            code: "E4003",
                            message: format!("validator calls unsupported function `{function}`"),
                            span: Span::default(),
                        });
                    }
                }
            }
        }
    }

    let mut complete = BTreeSet::new();
    for name in graph.keys() {
        if validator_graph_has_cycle(name, &graph, &mut BTreeSet::new(), &mut complete) {
            diagnostics.push(Diagnostic {
                code: "E4003",
                message: format!("validator recursion involving `{name}`"),
                span: Span::default(),
            });
            break;
        }
    }
}

fn validator_graph_has_cycle(
    name: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
    visiting: &mut BTreeSet<String>,
    complete: &mut BTreeSet<String>,
) -> bool {
    if !visiting.insert(name.to_owned()) {
        return true;
    }
    if complete.contains(name) {
        visiting.remove(name);
        return false;
    }
    if graph.get(name).is_some_and(|edges| {
        edges
            .iter()
            .any(|target| validator_graph_has_cycle(target, graph, visiting, complete))
    }) {
        return true;
    }
    visiting.remove(name);
    complete.insert(name.to_owned());
    false
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
    encode_dependencies(&mut canonical, &descriptor.dependencies);
    encode_types(&mut canonical, &descriptor.types);
    encode_validators(&mut canonical, &descriptor.validators);
    encode_events(&mut canonical, &descriptor.events);
    encode_tags(&mut canonical, &descriptor.tags);
    encode_operations(&mut canonical, &descriptor.operations);
    encode_errors(&mut canonical, &descriptor.errors);
    encode_vectors(&mut canonical, &descriptor.vectors);
    Sha256::digest(canonical).into()
}

fn encode_dependencies(output: &mut Vec<u8>, dependencies: &[ModuleDependency]) {
    let mut dependencies = dependencies.iter().collect::<Vec<_>>();
    dependencies.sort_by(|left, right| left.name.cmp(&right.name));
    encode_count(output, dependencies.len());
    for dependency in dependencies {
        encode_string(output, &dependency.name);
        encode_string(output, &dependency.requirement.to_string());
    }
}

fn encode_types(output: &mut Vec<u8>, types: &[TypeDefinition]) {
    let mut types = types.iter().collect::<Vec<_>>();
    types.sort_by_key(|item| item.name());
    encode_count(output, types.len());
    for item in types {
        match item {
            TypeDefinition::Nominal {
                name,
                base,
                requirements,
            } => {
                output.push(0);
                encode_string(output, name);
                encode_string(output, base);
                encode_sorted_strings(output, requirements);
            }
            TypeDefinition::Record { name, fields } => {
                output.push(1);
                encode_string(output, name);
                encode_fields(output, fields, true);
            }
            TypeDefinition::Enum { name, variants } => {
                output.push(2);
                encode_string(output, name);
                encode_sorted_strings(output, variants);
            }
        }
    }
}

fn encode_validators(output: &mut Vec<u8>, validators: &[ValidatorDefinition]) {
    let mut validators = validators.iter().collect::<Vec<_>>();
    validators.sort_by_key(|item| &item.name);
    encode_count(output, validators.len());
    for validator in validators {
        encode_string(output, &validator.name);
        encode_fields(output, &validator.parameters, false);
        encode_sorted_strings(output, &validator.requirements);
    }
}

fn encode_events(output: &mut Vec<u8>, events: &[EventDefinition]) {
    let mut events = events.iter().collect::<Vec<_>>();
    events.sort_by_key(|event| &event.name);
    encode_count(output, events.len());
    for event in events {
        encode_string(output, &event.name);
        output.extend_from_slice(&event.kind.to_be_bytes());
        output.push(match event.mode {
            EventMode::Regular => 0,
            EventMode::Replaceable => 1,
            EventMode::Addressable => 2,
            EventMode::Ephemeral => 3,
        });
        encode_string(output, &event.content_type);
        encode_option(output, event.content_encoding.as_deref());
        encode_option(output, event.tags_type.as_deref());
        encode_fields(output, &event.fields, true);
        encode_sorted_strings(output, &event.requirements);
    }
}

fn encode_tags(output: &mut Vec<u8>, tags: &[TagDefinition]) {
    let mut tags = tags.iter().collect::<Vec<_>>();
    tags.sort_by_key(|tag| &tag.name);
    encode_count(output, tags.len());
    for tag in tags {
        encode_string(output, &tag.name);
        encode_string(output, &tag.wire_name);
        encode_count(output, tag.slots.len());
        for slot in &tag.slots {
            match slot {
                TagSlot::Field {
                    name,
                    type_name,
                    position,
                } => {
                    output.push(0);
                    output.extend_from_slice(&position.to_be_bytes());
                    encode_string(output, name);
                    encode_string(output, type_name);
                }
                TagSlot::Literal { value, position } => {
                    output.push(1);
                    output.extend_from_slice(&position.to_be_bytes());
                    encode_string(output, value);
                }
            }
        }
        let mut validators = tag.validators.iter().collect::<Vec<_>>();
        validators.sort();
        encode_count(output, validators.len());
        for validator in validators {
            encode_string(output, validator);
        }
    }
}

fn encode_operations(output: &mut Vec<u8>, operations: &[HostOperation]) {
    let mut operations = operations.iter().collect::<Vec<_>>();
    operations.sort_by_key(|item| &item.name);
    encode_count(output, operations.len());
    for operation in operations {
        encode_string(output, &operation.name);
        encode_fields(output, &operation.parameters, false);
        encode_string(output, &operation.return_type);
        encode_sorted_strings(output, &operation.effects);
        encode_string(output, &operation.permission);
    }
}

fn encode_errors(output: &mut Vec<u8>, errors: &[ErrorDefinition]) {
    let mut errors = errors.iter().collect::<Vec<_>>();
    errors.sort_by_key(|item| &item.name);
    encode_count(output, errors.len());
    for error in errors {
        encode_string(output, &error.name);
        encode_fields(output, &error.fields, true);
    }
}

fn encode_vectors(output: &mut Vec<u8>, vectors: &[TestVector]) {
    let mut vectors = vectors.iter().collect::<Vec<_>>();
    vectors.sort_by_key(|item| &item.name);
    encode_count(output, vectors.len());
    for vector in vectors {
        encode_string(output, &vector.name);
        encode_string(output, &vector.value);
    }
}

fn encode_fields(output: &mut Vec<u8>, fields: &[SchemaField], sort_by_name: bool) {
    let mut fields = fields.iter().collect::<Vec<_>>();
    if sort_by_name {
        fields.sort_by_key(|field| &field.name);
    }
    encode_count(output, fields.len());
    for field in fields {
        encode_string(output, &field.name);
        encode_string(output, &field.type_name);
        encode_option(output, field.default.as_deref());
    }
}

fn encode_sorted_strings(output: &mut Vec<u8>, values: &[String]) {
    let mut values = values.iter().collect::<Vec<_>>();
    values.sort();
    encode_count(output, values.len());
    for value in values {
        encode_string(output, value);
    }
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
    const FULL_SCHEMA: &str = include_str!("../../../conformance/modules/valid/full-schema.nsm");

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
            "c5c46f80d62c7b75f112d255f831e991d2354e8684ebe6cef14a7c6a953ebe0f"
        );
    }

    #[test]
    fn parses_every_module_declaration_form() {
        let (descriptor, diagnostics) = parse_module(FULL_SCHEMA);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let descriptor = descriptor.expect("valid descriptor");
        assert_eq!(descriptor.dependencies.len(), 1);
        assert_eq!(descriptor.types.len(), 3);
        assert_eq!(descriptor.validators.len(), 2);
        assert_eq!(descriptor.events[0].fields.len(), 1);
        assert_eq!(descriptor.events[0].requirements.len(), 1);
        assert_eq!(descriptor.tags.len(), 1);
        assert_eq!(descriptor.operations.len(), 1);
        assert_eq!(descriptor.errors.len(), 1);
        assert_eq!(descriptor.vectors.len(), 1);
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
    fn declaration_and_record_field_order_do_not_change_hash() {
        let first = r#"
module example::ordering @ 1.0.0
language ">=0.1.0 <0.2.0"

record Person {
    field name: Text
    field pubkey: PubKey
}

enum Presence { Online, Offline }
"#;
        let second = r#"
module example::ordering @ 1.0.0
language ">=0.1.0 <0.2.0"

enum Presence { Offline, Online }

record Person {
    field pubkey: PubKey
    field name: Text
}
"#;
        let (first, first_diagnostics) = parse_module(first);
        let (second, second_diagnostics) = parse_module(second);
        assert!(first_diagnostics.is_empty(), "{first_diagnostics:#?}");
        assert!(second_diagnostics.is_empty(), "{second_diagnostics:#?}");
        assert_eq!(
            first.expect("valid descriptor").canonical_hash,
            second.expect("valid descriptor").canonical_hash
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

    #[test]
    fn rejects_recursive_validators() {
        let source = include_str!("../../../conformance/modules/invalid/recursive-validator.nsm");
        let (descriptor, diagnostics) = parse_module(source);
        assert!(descriptor.is_none());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("validator recursion"))
        );
    }

    #[test]
    fn rejects_unknown_effects_and_gapped_tags() {
        for source in [
            include_str!("../../../conformance/modules/invalid/unknown-effect.nsm"),
            include_str!("../../../conformance/modules/invalid/gapped-tag-position.nsm"),
        ] {
            let (descriptor, diagnostics) = parse_module(source);
            assert!(descriptor.is_none());
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "E4003")
            );
        }
    }
}
