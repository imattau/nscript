//! Editor analysis for `NScript`: an outline, completions, and hover text
//! derived from the parsed program and the resolved module graph.
//!
//! This is deliberately a light surface over the real checker, not a second
//! type system. Completions come from module descriptors (types, events,
//! functions, operations, tags) and from typed handler/stream event members;
//! hover text explains what a name is and where it comes from. Everything is
//! serializable so the wasm build can hand it to a browser editor directly.

use std::collections::{BTreeMap, BTreeSet};

use nscript_modules::{
    ModuleDependency, ModuleOrigin, ModuleRegistry, ResolutionError, TypeDefinition, parse_module,
};
use nscript_semantics::analyze_with_modules;
use nscript_syntax::{
    Diagnostic, Program, Span,
    ast::{ExprKind, Item, StatementKind, TypeRef},
    parse_program,
};
use serde::Serialize;

/// A parsed program with its resolved module graph and combined diagnostics,
/// ready for editor queries.
#[derive(Clone, Debug)]
pub struct AnalyzedProgram {
    pub program: Program,
    pub graph: nscript_modules::ResolvedModuleGraph,
    pub diagnostics: Vec<Diagnostic>,
    source: String,
}

/// Parses `source`, registers any custom `(name, source)` modules, resolves the
/// module graph, and runs the same structural analysis the CLI does.
#[must_use]
pub fn analyze(source: &str, modules: &[(&str, &str)]) -> AnalyzedProgram {
    let (program, mut diagnostics) = parse_program(source);
    let mut registry = ModuleRegistry::with_builtins();
    for (name, module_source) in modules {
        let (descriptor, mut module_diagnostics) = parse_module(module_source);
        diagnostics.append(&mut module_diagnostics);
        if let Some(descriptor) = descriptor
            && let Err(error) =
                registry.register(descriptor, ModuleOrigin::BuiltIn((*name).to_owned()))
        {
            diagnostics.push(Diagnostic {
                code: "E4003",
                message: error.to_string(),
                span: Span::default(),
            });
        }
    }
    let mut roots = Vec::new();
    for import in &program.imports {
        let requirement_text = import.requirement.as_deref().unwrap_or("*");
        let normalized = requirement_text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(", ");
        match semver::VersionReq::parse(&normalized) {
            Ok(requirement) => roots.push(ModuleDependency {
                name: import.path.clone(),
                requirement,
            }),
            Err(error) => diagnostics.push(Diagnostic {
                code: "E4002",
                message: format!("invalid module requirement `{requirement_text}`: {error}"),
                span: import.span,
            }),
        }
    }
    let graph = match registry.resolve(&roots) {
        Ok(graph) => graph,
        Err(error) => {
            let code = match &error {
                ResolutionError::Cycle(_) => "E4001",
                ResolutionError::Missing { .. } => "E4002",
                ResolutionError::Conflict { .. } => "E4003",
            };
            diagnostics.push(Diagnostic {
                code,
                message: error.to_string(),
                span: program
                    .imports
                    .first()
                    .map_or_else(Span::default, |import| import.span),
            });
            // Keep every registered module name even when the current import
            // does not resolve yet, so the editor can still offer modules on an
            // incomplete `use` line.
            let known = registry
                .resolve(&[])
                .map_or_else(|_| BTreeSet::new(), |graph| graph.known);
            nscript_modules::ResolvedModuleGraph {
                modules: BTreeMap::new(),
                known,
            }
        }
    };
    diagnostics.extend(analyze_with_modules(&program, &graph));
    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    AnalyzedProgram {
        program,
        graph,
        diagnostics,
        source: source.to_owned(),
    }
}

/// One top-level declaration for an outline panel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Symbol {
    pub name: String,
    /// `module`, `signer`, `relay`, `relayset`, `key`, `store`, `event`,
    /// `function`, `stream`, `let`, or `handler`.
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
    pub detail: String,
}

/// Lists the top-level declarations of a program in source order.
#[must_use]
pub fn symbols(analysis: &AnalyzedProgram) -> Vec<Symbol> {
    let mut out = Vec::new();
    for item in &analysis.program.ast.items {
        let symbol = match item {
            Item::Use(import) => Symbol {
                name: import.path.clone(),
                kind: "module",
                start: import.span.start,
                end: import.span.end,
                detail: format!("use {}", import.requirement.as_deref().unwrap_or("*")),
            },
            Item::Signer(declaration) => capability_symbol(declaration, "signer"),
            Item::Relay(declaration) => capability_symbol(declaration, "relay"),
            Item::RelaySet(declaration) => capability_symbol(declaration, "relayset"),
            Item::Key(declaration) => capability_symbol(declaration, "key"),
            Item::Store(store) => Symbol {
                name: store.name.value.clone(),
                kind: "store",
                start: store.span.start,
                end: store.span.end,
                detail: store_type(&store.value_type),
            },
            Item::Event(event) => Symbol {
                name: event.name.value.clone(),
                kind: "event",
                start: event.span.start,
                end: event.span.end,
                detail: event
                    .kind
                    .map_or_else(|| "event".to_owned(), |kind| format!("kind {kind}")),
            },
            Item::Function(function) => Symbol {
                name: function.name.value.clone(),
                kind: "function",
                start: function.span.start,
                end: function.span.end,
                detail: function_signature(function),
            },
            Item::Stream { name, value, span } => Symbol {
                name: name.value.clone(),
                kind: "stream",
                start: span.start,
                end: span.end,
                detail: stream_detail(value),
            },
            Item::Let(declaration) => Symbol {
                name: declaration.name.value.clone(),
                kind: "let",
                start: declaration.span.start,
                end: declaration.span.end,
                detail: declaration
                    .type_annotation
                    .as_ref()
                    .map_or_else(|| "let".to_owned(), type_name),
            },
            Item::Statement(statement) => match &statement.value {
                StatementKind::On { source, .. } => Symbol {
                    name: format!("on {}", handler_source_name(source)),
                    kind: "handler",
                    start: statement.span.start,
                    end: statement.span.end,
                    detail: "handler".to_owned(),
                },
                _ => continue,
            },
            _ => continue,
        };
        out.push(symbol);
    }
    out
}

fn capability_symbol(
    declaration: &nscript_syntax::ast::CapabilityDeclaration,
    kind: &'static str,
) -> Symbol {
    Symbol {
        name: declaration.name.value.clone(),
        kind,
        start: declaration.span.start,
        end: declaration.span.end,
        detail: kind.to_owned(),
    }
}

fn store_type(type_ref: &TypeRef) -> String {
    type_name(type_ref)
}

#[must_use]
fn type_name(type_ref: &TypeRef) -> String {
    if type_ref.arguments.is_empty() {
        type_ref.name.clone()
    } else {
        format!(
            "{}<{}>",
            type_ref.name,
            type_ref
                .arguments
                .iter()
                .map(type_name)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn function_signature(function: &nscript_syntax::ast::FunctionDeclaration) -> String {
    let parameters = function
        .parameters
        .iter()
        .map(|parameter| {
            format!(
                "{}: {}",
                parameter.name.value,
                type_name(&parameter.type_ref)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    function.return_type.as_ref().map_or_else(
        || format!("fn {}({parameters})", function.name.value),
        |return_type| {
            format!(
                "fn {}({parameters}) -> {}",
                function.name.value,
                type_name(return_type)
            )
        },
    )
}

fn stream_detail(value: &nscript_syntax::ast::Expr) -> String {
    match &value.value {
        ExprKind::Select(select) => format!("select {}", type_name(&select.event)),
        _ => "stream".to_owned(),
    }
}

fn handler_source_name(source: &nscript_syntax::ast::Expr) -> String {
    match &source.value {
        ExprKind::Identifier(name) => name.clone(),
        ExprKind::Construct { name, .. } => name.value.clone(),
        _ => "event".to_owned(),
    }
}

/// A completion candidate for the editor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Completion {
    pub label: String,
    /// `keyword`, `module`, `type`, `event`, `function`, `operation`, `tag`,
    /// `field`, or `variable`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub insert: String,
}

/// Completions at a byte `offset` in the source.
///
/// Contexts handled: a `use` line offers module names, `module.` offers module
/// exports, `event.` and stream `.` offer typed event members, and anywhere
/// else offers statement keywords plus local names.
#[must_use]
pub fn completions(analysis: &AnalyzedProgram, offset: usize) -> Vec<Completion> {
    let (start, _, _) = word_at(&analysis.source, offset);
    if let Some(base) = base_before(&analysis.source, start) {
        if is_module(analysis, &base) {
            return module_exports(analysis, &base);
        }
        if base == "event" {
            return event_type_at(analysis, offset)
                .map_or_else(signed_event_fields, |event_type| {
                    event_fields(analysis, &event_type)
                });
        }
        if let Some(event_type) = stream_event_type(analysis, &base) {
            return event_fields(analysis, &event_type);
        }
        return Vec::new();
    }
    let mut out = Vec::new();
    let line_prefix = line_prefix(&analysis.source, start).trim();
    if line_prefix == "use" || line_prefix.starts_with("use ") {
        for name in module_names(analysis) {
            out.push(Completion {
                label: name.clone(),
                kind: "module",
                detail: module_detail(analysis, &name),
                insert: name,
            });
        }
        return out;
    }
    for keyword in STATEMENT_KEYWORDS {
        out.push(Completion {
            label: (*keyword).to_owned(),
            kind: "keyword",
            detail: None,
            insert: (*keyword).to_owned(),
        });
    }
    for name in local_names(analysis) {
        out.push(Completion {
            label: name.clone(),
            kind: "variable",
            detail: local_detail(analysis, &name),
            insert: name,
        });
    }
    for name in module_names(analysis) {
        out.push(Completion {
            label: name.clone(),
            kind: "module",
            detail: module_detail(analysis, &name),
            insert: name,
        });
    }
    out
}

const STATEMENT_KEYWORDS: &[&str] = &[
    "assert",
    "at",
    "badge",
    "ban",
    "calendar",
    "comment",
    "defaults",
    "delete",
    "draft",
    "every",
    "file",
    "fn",
    "for",
    "handler",
    "highlight",
    "if",
    "image",
    "key",
    "kick",
    "label",
    "let",
    "live",
    "match",
    "on",
    "once",
    "permissions",
    "publish",
    "react",
    "relay",
    "relayset",
    "repost",
    "report",
    "return",
    "runtime",
    "say",
    "search",
    "send",
    "signer",
    "status",
    "store",
    "upload",
    "use",
    "video",
    "zap",
];

/// A hover card for the editor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Hover {
    pub label: String,
    pub detail: String,
}

/// Hover text for the identifier under a byte `offset`.
#[must_use]
pub fn hover(analysis: &AnalyzedProgram, offset: usize) -> Option<Hover> {
    let (start, _, word) = word_at(&analysis.source, offset);
    if word.is_empty() {
        return None;
    }
    if let Some(base) = base_before(&analysis.source, start) {
        if is_module(analysis, &base) {
            return module_member_hover(analysis, &base, &word);
        }
        if base == "event" {
            let event_type = event_type_at(analysis, offset).unwrap_or_else(|| "Event".to_owned());
            return Some(Hover {
                label: "event".to_owned(),
                detail: format!("Signed<{event_type}>"),
            });
        }
        if let Some(event_type) = stream_event_type(analysis, &base) {
            return Some(Hover {
                label: base,
                detail: format!("stream of {event_type}"),
            });
        }
        return None;
    }
    if is_module(analysis, &word) {
        return module_hover(analysis, &word);
    }
    if core_type(&word) {
        return Some(Hover {
            label: word,
            detail: "core type".to_owned(),
        });
    }
    local_hover(analysis, &word)
}

fn is_module(analysis: &AnalyzedProgram, name: &str) -> bool {
    analysis.graph.modules.contains_key(name)
}

fn module_names(analysis: &AnalyzedProgram) -> Vec<String> {
    analysis.graph.known.iter().cloned().collect()
}

fn module_detail(analysis: &AnalyzedProgram, name: &str) -> Option<String> {
    let registered = analysis.graph.modules.get(name)?;
    Some(format!(
        "{}@{}",
        registered.descriptor.id.name, registered.descriptor.id.version
    ))
}

fn module_hover(analysis: &AnalyzedProgram, name: &str) -> Option<Hover> {
    use std::fmt::Write as _;

    let registered = analysis.graph.modules.get(name)?;
    let descriptor = &registered.descriptor;
    let mut detail = format!(
        "module {}@{} (canonical {})",
        descriptor.id.name, descriptor.id.version, descriptor.language
    );
    if let Some(reference) = &descriptor.reference {
        let _ = write!(detail, "\n{reference}");
    }
    Some(Hover {
        label: name.to_owned(),
        detail,
    })
}

fn module_member_hover(analysis: &AnalyzedProgram, module: &str, name: &str) -> Option<Hover> {
    let registered = analysis.graph.modules.get(module)?;
    let descriptor = &registered.descriptor;
    for operation in &descriptor.operations {
        if operation.name == name {
            return Some(Hover {
                label: format!("{module}.{name}"),
                detail: operation_signature(operation),
            });
        }
    }
    for function in &descriptor.functions {
        if function.name == name {
            return Some(Hover {
                label: format!("{module}.{name}"),
                detail: function_signature_descriptor(module, function),
            });
        }
    }
    for event in &descriptor.events {
        if event.name == name {
            return Some(Hover {
                label: format!("{module}.{name}"),
                detail: format!("event kind {} ({:?})", event.kind, event.mode),
            });
        }
    }
    for type_definition in &descriptor.types {
        if type_definition.name() == name {
            return Some(Hover {
                label: format!("{module}.{name}"),
                detail: type_definition_detail(type_definition),
            });
        }
    }
    None
}

fn module_exports(analysis: &AnalyzedProgram, module: &str) -> Vec<Completion> {
    let Some(registered) = analysis.graph.modules.get(module) else {
        return Vec::new();
    };
    let descriptor = &registered.descriptor;
    let mut out = Vec::new();
    for type_definition in &descriptor.types {
        out.push(Completion {
            label: type_definition.name().to_owned(),
            kind: "type",
            detail: Some(type_definition_detail(type_definition)),
            insert: type_definition.name().to_owned(),
        });
    }
    for event in &descriptor.events {
        out.push(Completion {
            label: event.name.clone(),
            kind: "event",
            detail: Some(format!("kind {}", event.kind)),
            insert: event.name.clone(),
        });
    }
    for function in &descriptor.functions {
        out.push(Completion {
            label: function.name.clone(),
            kind: "function",
            detail: Some(function_signature_descriptor(module, function)),
            insert: function.name.clone(),
        });
    }
    for operation in &descriptor.operations {
        out.push(Completion {
            label: operation.name.clone(),
            kind: "operation",
            detail: Some(operation_signature(operation)),
            insert: operation.name.clone(),
        });
    }
    for tag in &descriptor.tags {
        out.push(Completion {
            label: tag.name.clone(),
            kind: "tag",
            detail: Some(format!("wire `{}`", tag.wire_name)),
            insert: tag.name.clone(),
        });
    }
    out.sort_by(|left, right| left.label.cmp(&right.label));
    out
}

fn type_definition_detail(type_definition: &TypeDefinition) -> String {
    match type_definition {
        TypeDefinition::Nominal { base, .. } => format!("nominal {base}"),
        TypeDefinition::Record { fields, .. } => {
            if fields.is_empty() {
                "record".to_owned()
            } else {
                format!(
                    "record {{{}}}",
                    fields
                        .iter()
                        .map(|field| field.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
        TypeDefinition::Enum { variants, .. } => {
            format!("enum {}", variants.join(" | "))
        }
    }
}

fn operation_signature(operation: &nscript_modules::HostOperation) -> String {
    let parameters = operation
        .parameters
        .iter()
        .map(|parameter| format!("{}: {}", parameter.name, parameter.type_name))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}({parameters}) -> {} · {}",
        operation.name, operation.return_type, operation.permission
    )
}

fn function_signature_descriptor(
    module: &str,
    function: &nscript_modules::FunctionDefinition,
) -> String {
    let parameters = function
        .parameters
        .iter()
        .map(|parameter| format!("{}: {}", parameter.name, parameter.type_name))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{module}.{}({parameters}) -> {}",
        function.name, function.return_type
    )
}

fn signed_event_fields() -> Vec<Completion> {
    ["id", "author", "content", "created_at", "kind", "tags"]
        .iter()
        .map(|name| Completion {
            label: (*name).to_owned(),
            kind: "field",
            detail: None,
            insert: (*name).to_owned(),
        })
        .collect()
}

fn event_fields(analysis: &AnalyzedProgram, event_type: &str) -> Vec<Completion> {
    let mut out = signed_event_fields();
    for registered in analysis.graph.modules.values() {
        if let Some(event) = registered
            .descriptor
            .events
            .iter()
            .find(|event| event.name == event_type)
        {
            for field in &event.fields {
                out.push(Completion {
                    label: field.name.clone(),
                    kind: "field",
                    detail: Some(field.type_name.clone()),
                    insert: field.name.clone(),
                });
            }
        }
    }
    out
}

/// The event type bound to `event` at `offset`, resolved through the enclosing
/// handler's source and any stream it names.
fn event_type_at(analysis: &AnalyzedProgram, offset: usize) -> Option<String> {
    for item in &analysis.program.ast.items {
        let Item::Statement(statement) = item else {
            continue;
        };
        let StatementKind::On { source, .. } = &statement.value else {
            continue;
        };
        if offset < statement.span.start || offset > statement.span.end {
            continue;
        }
        let name = handler_source_name(source);
        return stream_event_type(analysis, &name).or_else(|| {
            analysis.graph.modules.values().find_map(|registered| {
                registered
                    .descriptor
                    .events
                    .iter()
                    .any(|event| event.name == name)
                    .then_some(name.clone())
            })
        });
    }
    None
}

fn stream_event_type(analysis: &AnalyzedProgram, name: &str) -> Option<String> {
    for item in &analysis.program.ast.items {
        let Item::Stream {
            name: stream_name,
            value,
            ..
        } = item
        else {
            continue;
        };
        if stream_name.value != name {
            continue;
        }
        if let ExprKind::Select(select) = &value.value {
            return Some(type_name(&select.event));
        }
    }
    None
}

fn local_names(analysis: &AnalyzedProgram) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for item in &analysis.program.ast.items {
        match item {
            Item::Signer(declaration)
            | Item::Relay(declaration)
            | Item::RelaySet(declaration)
            | Item::Key(declaration) => {
                names.insert(declaration.name.value.clone());
            }
            Item::Store(store) => {
                names.insert(store.name.value.clone());
            }
            Item::Event(event) => {
                names.insert(event.name.value.clone());
            }
            Item::Function(function) => {
                names.insert(function.name.value.clone());
            }
            Item::Stream { name, .. } => {
                names.insert(name.value.clone());
            }
            Item::Let(declaration) => {
                names.insert(declaration.name.value.clone());
            }
            _ => {}
        }
    }
    names.insert("event".to_owned());
    names
}

fn local_detail(analysis: &AnalyzedProgram, name: &str) -> Option<String> {
    for item in &analysis.program.ast.items {
        match item {
            Item::Signer(declaration) if declaration.name.value == name => {
                return Some("signer".to_owned());
            }
            Item::Relay(declaration) if declaration.name.value == name => {
                return Some("relay".to_owned());
            }
            Item::RelaySet(declaration) if declaration.name.value == name => {
                return Some("relayset".to_owned());
            }
            Item::Key(declaration) if declaration.name.value == name => {
                return Some("host-held key".to_owned());
            }
            Item::Store(store) if store.name.value == name => {
                return Some(format!("store {}", store_type(&store.value_type)));
            }
            Item::Event(event) if event.name.value == name => {
                return Some("event type".to_owned());
            }
            Item::Function(function) if function.name.value == name => {
                return Some(function_signature(function));
            }
            Item::Stream { name: stream, .. } if stream.value == name => {
                return Some("stream".to_owned());
            }
            _ => {}
        }
    }
    if name == "event" {
        return Some("Signed<Event>".to_owned());
    }
    None
}

fn local_hover(analysis: &AnalyzedProgram, name: &str) -> Option<Hover> {
    local_detail(analysis, name).map(|detail| Hover {
        label: name.to_owned(),
        detail,
    })
}

fn core_type(name: &str) -> bool {
    matches!(
        name,
        "Bool"
            | "Int"
            | "Decimal"
            | "Text"
            | "Bytes"
            | "Duration"
            | "Percentage"
            | "Unit"
            | "Never"
            | "List"
            | "Set"
            | "Map"
            | "Option"
            | "Result"
            | "PubKey"
            | "EventId"
            | "Signature"
            | "RelayUrl"
            | "Timestamp"
            | "Kind"
            | "Nprofile"
            | "Nevent"
            | "Naddr"
            | "Nsec"
            | "Signer"
            | "SecretKey"
            | "Tag"
    )
}

/// The identifier containing or touching `offset`, as a byte range.
#[must_use]
fn word_at(source: &str, offset: usize) -> (usize, usize, String) {
    let bytes = source.as_bytes();
    let offset = offset.min(bytes.len());
    let mut start = offset;
    while start > 0 && is_word(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = offset;
    while end < bytes.len() && is_word(bytes[end]) {
        end += 1;
    }
    (
        start,
        end,
        String::from_utf8_lossy(&bytes[start..end]).into_owned(),
    )
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The identifier immediately preceding `start` when it is a member access
/// (`base.`), so completions can offer that base's members.
#[must_use]
fn base_before(source: &str, start: usize) -> Option<String> {
    let bytes = source.as_bytes();
    if start == 0 || bytes[start - 1] != b'.' {
        return None;
    }
    let index = start - 1;
    let mut ident_start = index;
    while ident_start > 0 && is_word(bytes[ident_start - 1]) {
        ident_start -= 1;
    }
    let base = &source[ident_start..index];
    (!base.is_empty()).then(|| base.to_owned())
}

#[must_use]
fn line_prefix(source: &str, start: usize) -> &str {
    let newline = source[..start].rfind('\n').map_or(0, |index| index + 1);
    &source[newline..start]
}

#[cfg(test)]
mod tests {
    use super::{analyze, completions, hover, symbols};

    fn analyzed(source: &str) -> super::AnalyzedProgram {
        analyze(source, &[])
    }

    #[test]
    fn outline_lists_top_level_declarations() {
        let analysis = analyzed(
            "use nip17\nsigner account = nip46()\nrelayset public = configured\nstore Seen<Set<EventId>>\non PrivateMessage {\n    print(event.content)\n}\n",
        );
        let names = symbols(&analysis)
            .into_iter()
            .map(|symbol| (symbol.name, symbol.kind))
            .collect::<Vec<_>>();
        assert!(names.contains(&("nip17".to_owned(), "module")));
        assert!(names.contains(&("account".to_owned(), "signer")));
        assert!(names.contains(&("public".to_owned(), "relayset")));
        assert!(names.contains(&("Seen".to_owned(), "store")));
        assert!(names.contains(&("on PrivateMessage".to_owned(), "handler")));
    }

    #[test]
    fn use_line_offers_module_names() {
        let source = "use nip\n";
        let completion = completions(&analyzed(source), source.len() - 1);
        let labels = completion.into_iter().map(|c| c.label).collect::<Vec<_>>();
        assert!(labels.contains(&"nip17".to_owned()), "{labels:?}");
        assert!(labels.contains(&"nip01".to_owned()), "{labels:?}");
        assert!(labels.contains(&"concord01".to_owned()), "{labels:?}");
    }

    #[test]
    fn module_member_completion_lists_exports() {
        let source = "use nip57\nzap alice amount 1000\nnip57.\n";
        let offset = source.rfind("nip57.").unwrap() + "nip57.".len();
        let completion = completions(&analyzed(source), offset);
        let labels = completion
            .into_iter()
            .map(|c| (c.label, c.kind))
            .collect::<Vec<_>>();
        assert!(
            labels.contains(&("create_zap_request".to_owned(), "operation")),
            "{labels:?}"
        );
        assert!(
            labels.contains(&("ZapRequest".to_owned(), "type")),
            "{labels:?}"
        );
    }

    #[test]
    fn handler_event_member_completion_is_typed() {
        let source = "use nip01\non Note {\n    event.\n}\n";
        let offset = source.rfind("event.").unwrap() + "event.".len();
        let completion = completions(&analyzed(source), offset);
        let labels = completion.into_iter().map(|c| c.label).collect::<Vec<_>>();
        assert!(labels.contains(&"content".to_owned()));
        assert!(labels.contains(&"author".to_owned()));
        assert!(labels.contains(&"id".to_owned()));
    }

    #[test]
    fn hover_explains_a_module_and_an_operation() {
        let source = "use nip57\nnip57.create_zap_request\n";
        let module = source.find("nip57\n").unwrap() + 1;
        let hovered = hover(&analyzed(source), module).expect("module hover");
        assert_eq!(hovered.label, "nip57");
        assert!(hovered.detail.contains("0.1.0"));
        let operation = source.find("create_zap_request").unwrap() + 5;
        let hovered = hover(&analyzed(source), operation).expect("operation hover");
        assert_eq!(hovered.label, "nip57.create_zap_request");
        assert!(hovered.detail.contains("zap"));
    }

    #[test]
    fn hover_types_the_handler_event_binding() {
        let source = "use nip01\non Note {\n    event\n}\n";
        let offset = source.find("event").unwrap() + 2;
        let hover = hover(&analyzed(source), offset).expect("event hover");
        assert_eq!(hover.label, "event");
        assert!(hover.detail.contains("Signed<"));
    }

    #[test]
    fn completions_do_not_panic_across_the_conformance_corpus() {
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/valid");
        for entry in std::fs::read_dir(&directory).expect("conformance directory") {
            let path = entry.expect("entry").path();
            if path.extension().is_none_or(|extension| extension != "ns") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read");
            let analysis = analyzed(&source);
            let offset = source.len() / 2;
            let _ = completions(&analysis, offset);
            let _ = hover(&analysis, offset);
        }
    }
}
