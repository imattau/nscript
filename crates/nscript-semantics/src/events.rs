//! Static typing of a handler's `event`.
//!
//! A handler's `event` has the type of what it listens to. For `on Note` that is
//! the `Note` event; for `on messages`, where `messages` is a stream, it is the
//! stream's element type (`StreamMessage`). The type's fields come from the
//! module descriptors (`event Note { content: Text .. }`, `record StreamMessage
//! { author: PubKey .. }`) or the program's own `event` declarations, and every
//! event also carries the fields of the signed event itself.
//!
//! With that, the checker can tell before a script runs that `event.contnet` does
//! not exist, that a record pattern names a field the event lacks, and that
//! `kick event.content` passes a `Text` where a `PubKey` is required.

use std::collections::{BTreeMap, BTreeSet};

use nscript_modules::{ResolvedModuleGraph, TagDefinition, TagSlot, TypeDefinition};
use nscript_syntax::ast::{
    EventDeclaration, Expr, ExprKind, Item, PatternKind, Spanned, StatementKind,
};
use nscript_syntax::{Diagnostic, Program, Span};

use crate::requirements::{self, Literal, Outcome};

/// The fields every delivered event has, whatever its type.
const COMMON_FIELDS: [(&str, &str); 7] = [
    ("id", "EventId"),
    ("author", "PubKey"),
    ("pubkey", "PubKey"),
    ("content", "Text"),
    ("kind", "Int"),
    ("created_at", "Int"),
    ("tags", "List<Text>"),
];

/// Types the checker will compare. Anything else (a record, a generic, an
/// unknown name) is left unchecked: a wrong guess would reject a valid program.
const SCALARS: [&str; 5] = ["Text", "Int", "Bool", "PubKey", "EventId"];

/// The type a handler's `event` has: the element type of a stream it listens to,
/// or the named event type.
pub(crate) fn handler_event_type(source: &Expr, program: &Program) -> Option<String> {
    match &source.value {
        ExprKind::Identifier(name) => Some(
            streams(program)
                .remove(name.as_str())
                .unwrap_or_else(|| name.clone()),
        ),
        ExprKind::Construct { name, .. } => Some(name.value.clone()),
        _ => None,
    }
}

/// Stream name to the event type its `select` yields.
fn streams(program: &Program) -> BTreeMap<&str, String> {
    program
        .ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Stream { name, value, .. } => match &value.value {
                ExprKind::Select(select) => Some((name.value.as_str(), select.event.name.clone())),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Checks every handler's use of `event` and of values derived from it.
pub(crate) fn validate(program: &Program, graph: &ResolvedModuleGraph) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let mut handlers = Vec::new();
    collect_handlers(&program.ast.items, &mut handlers);
    for (source, body) in handlers {
        let Some(event_type) = handler_event_type(source, program) else {
            continue;
        };
        // An event type nothing defines cannot be checked, and must not be
        // guessed at.
        let Some(fields) = event_fields(&event_type, program, graph) else {
            continue;
        };
        if declares_event(body) {
            continue;
        }
        let mut checker = HandlerChecker {
            event_type: &event_type,
            fields: &fields,
            program,
            graph,
            diagnostics: &mut diagnostics,
        };
        checker.block(body, &mut BTreeMap::new());
    }
    diagnostics
}

/// Reject publication shapes that would silently drop or misplace wire data:
/// nominal tag records that do not match the declared type of the published
/// event field, author fields the declared event (or tag) does not know,
/// read-side fields that never lower, and records missing a field the
/// declaration requires.
pub(crate) fn validate_publication_tag_types(
    program: &Program,
    graph: &ResolvedModuleGraph,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let context = PublicationContext { program, graph };
    validate_publication_items(&program.ast.items, &context, &mut diagnostics);
    diagnostics
}

struct PublicationContext<'a> {
    program: &'a Program,
    graph: &'a ResolvedModuleGraph,
}

/// A declared event as the program sees it. A program's own declaration
/// shadows an imported module's, as it does for publication lowering.
struct VisibleEvent {
    /// Declared author field name to its declared type name.
    fields: BTreeMap<String, String>,
    /// The event declares a free-form `tags: List<Tag>`, so every author field
    /// is a legitimate NIP-01 tag and only read-side names are rejected.
    open: bool,
    /// The module's `require` lines. Program event declarations have none.
    requirements: Vec<String>,
    /// The module the declaration came from; `None` for a program event.
    module: Option<String>,
}

impl VisibleEvent {
    fn field_type(&self, field: &str) -> Option<&str> {
        self.fields.get(field).map(String::as_str)
    }
}

/// Read-side event fields: publishing one silently lowers to nothing, so it is
/// rejected rather than ignored. These are exactly the names the record
/// lowering skips (`EVENT_BOOKKEEPING_FIELDS`), plus the event's own `tags`.
const READ_ONLY_FIELDS: [&str; 6] = ["id", "author", "pubkey", "kind", "created_at", "tags"];

fn read_only_reason(field: &str) -> &'static str {
    match field {
        "id" => "the event id is computed when it is signed",
        "author" | "pubkey" => "the signer supplies it",
        "kind" => "the event declaration supplies it",
        "created_at" => "the runtime supplies it",
        "tags" => "write each tag as a named field instead",
        _ => "it is read-side only",
    }
}

fn validate_publication_items(
    items: &[Item],
    context: &PublicationContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for item in items {
        match item {
            Item::Let(declaration) => {
                validate_publication_expr(&declaration.value, context, diagnostics);
            }
            Item::Function(function) => {
                validate_publication_items(&function.body, context, diagnostics);
            }
            Item::Stream { value, .. } => validate_publication_expr(value, context, diagnostics),
            Item::Statement(statement) => {
                validate_publication_statement(&statement.value, context, diagnostics);
            }
            _ => {}
        }
    }
}

fn validate_publication_statement(
    statement: &StatementKind,
    context: &PublicationContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match statement {
        StatementKind::Expression(value) | StatementKind::Return(Some(value)) => {
            validate_publication_expr(value, context, diagnostics);
        }
        StatementKind::For { value, body, .. } => {
            validate_publication_expr(value, context, diagnostics);
            validate_publication_items(body, context, diagnostics);
        }
        StatementKind::If {
            condition,
            then_body,
            else_body,
        } => {
            validate_publication_expr(condition, context, diagnostics);
            validate_publication_items(then_body, context, diagnostics);
            validate_publication_items(else_body, context, diagnostics);
        }
        StatementKind::On {
            source,
            predicate,
            body,
        } => {
            validate_publication_expr(source, context, diagnostics);
            if let Some(predicate) = predicate {
                validate_publication_expr(predicate, context, diagnostics);
            }
            validate_publication_items(body, context, diagnostics);
        }
        StatementKind::Once { key, body } => {
            validate_publication_expr(key, context, diagnostics);
            validate_publication_items(body, context, diagnostics);
        }
        StatementKind::Every { duration, body } => {
            validate_publication_expr(duration, context, diagnostics);
            validate_publication_items(body, context, diagnostics);
        }
        StatementKind::At { schedule, body } => {
            validate_publication_expr(schedule, context, diagnostics);
            validate_publication_items(body, context, diagnostics);
        }
        StatementKind::Send { value, signer } => {
            validate_publication_expr(value, context, diagnostics);
            if let Some(signer) = signer {
                validate_publication_expr(signer, context, diagnostics);
            }
        }
        StatementKind::Return(None) => {}
    }
}

#[allow(clippy::too_many_lines)]
fn validate_publication_expr(
    expression: &Expr,
    context: &PublicationContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_constructor_fields(expression, context, diagnostics);

    match &expression.value {
        ExprKind::Call { callee, arguments } => {
            validate_publication_expr(callee, context, diagnostics);
            for argument in arguments {
                validate_publication_expr(argument, context, diagnostics);
            }
        }
        ExprKind::Member { value, .. }
        | ExprKind::Propagate(value)
        | ExprKind::Unary { value, .. }
        | ExprKind::Fetch { url: value, .. } => {
            validate_publication_expr(value, context, diagnostics);
        }
        ExprKind::Sign { value, signer } => {
            validate_publication_expr(value, context, diagnostics);
            validate_publication_expr(signer, context, diagnostics);
        }
        ExprKind::Publish {
            value,
            relays,
            signer,
        } => {
            validate_publication_expr(value, context, diagnostics);
            if let Some(relays) = relays {
                validate_publication_expr(relays, context, diagnostics);
            }
            if let Some(signer) = signer {
                validate_publication_expr(signer, context, diagnostics);
            }
        }
        ExprKind::Binary { left, right, .. }
        | ExprKind::Assign {
            target: left,
            value: right,
        }
        | ExprKind::Index {
            value: left,
            index: right,
        } => {
            validate_publication_expr(left, context, diagnostics);
            validate_publication_expr(right, context, diagnostics);
        }
        ExprKind::List(values) => {
            for value in values {
                validate_publication_expr(value, context, diagnostics);
            }
        }
        ExprKind::Latest {
            arguments, relays, ..
        } => {
            for argument in arguments {
                validate_publication_expr(argument, context, diagnostics);
            }
            if let Some(relays) = relays {
                validate_publication_expr(relays, context, diagnostics);
            }
        }
        ExprKind::Record(fields) | ExprKind::Construct { fields, .. } => {
            for (_, value) in fields {
                validate_publication_expr(value, context, diagnostics);
            }
        }
        ExprKind::Select(select) => {
            for expression in [
                select.predicate.as_deref(),
                select.since.as_deref(),
                select.until.as_deref(),
                select.relays.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_publication_expr(expression, context, diagnostics);
            }
        }
        ExprKind::Match { value, arms } => {
            validate_publication_expr(value, context, diagnostics);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    validate_publication_expr(guard, context, diagnostics);
                }
                validate_publication_expr(&arm.value, context, diagnostics);
            }
        }
        _ => {}
    }
}

/// Reject publication shapes that would silently drop or misplace wire data.
/// Every publish field lowers to a wire tag named after it, so an unknown name
/// publishes well-formed Nostr carrying a tag the event never declares, and a
/// read-side name lowers to nothing at all.
fn check_constructor_fields(
    expression: &Expr,
    context: &PublicationContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let ExprKind::Construct { name, fields } = &expression.value else {
        return;
    };
    if let Some(event) = visible_event(&name.value, context.program, context.graph) {
        check_event_constructor(
            &name.value,
            &event,
            fields,
            expression.span,
            context,
            diagnostics,
        );
        return;
    }
    let Some((module, tag)) = visible_tag(&name.value, context.graph) else {
        return;
    };
    let slots = tag_slot_names(tag);
    for (field, _) in fields {
        if slots.contains(&field.value) {
            continue;
        }
        diagnostics.push(Diagnostic {
            code: "E2407",
            message: format!(
                "tag `{}` has no field `{}`; it declares: {}",
                name.value,
                field.value,
                field_list(&slots)
            ),
            span: field.span,
        });
    }
    let context_fields = literal_fields(fields);
    if let Outcome::Violated(requirement) =
        requirements::evaluate(&tag.validators, &context_fields, module, context.graph)
    {
        diagnostics.push(Diagnostic {
            code: "E2409",
            message: format!(
                "tag `{}` does not satisfy requirement `{requirement}` from module `{module}`",
                name.value
            ),
            span: requirement_span(&requirement, fields, expression.span),
        });
    }
}

fn check_event_constructor(
    event_name: &str,
    event: &VisibleEvent,
    fields: &[(nscript_syntax::ast::Spanned<String>, Expr)],
    span: Span,
    context: &PublicationContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let accepted = event
        .fields
        .keys()
        .cloned()
        .chain(std::iter::once("content".to_owned()))
        .collect::<BTreeSet<_>>();
    for (field, value) in fields {
        if let Some(reason) = read_only_field(&field.value) {
            diagnostics.push(Diagnostic {
                code: "E2408",
                message: format!(
                    "event `{event_name}` cannot set `{}`: {reason}",
                    field.value
                ),
                span: field.span,
            });
            continue;
        }
        if !event.open && !accepted.contains(&field.value) {
            diagnostics.push(Diagnostic {
                code: "E2407",
                message: format!(
                    "event `{event_name}` has no author field `{}`; its fields are: {}",
                    field.value,
                    field_list(&accepted),
                ),
                span: field.span,
            });
            continue;
        }
        let Some(declared_type) = event.field_type(&field.value) else {
            continue;
        };
        let Some((_, tag)) = visible_tag(declared_type, context.graph) else {
            continue;
        };
        let ExprKind::Construct { name: actual, .. } = &value.value else {
            continue;
        };
        if actual.value != tag.name {
            diagnostics.push(Diagnostic {
                code: "E2405",
                message: format!(
                    "event field `{event_name}.{}` requires tag type `{}`, found `{}`",
                    field.value, tag.name, actual.value
                ),
                span: value.span,
            });
        }
    }
    let declared = fields
        .iter()
        .map(|(name, _)| name.value.as_str())
        .collect::<BTreeSet<_>>();
    for required_name in event
        .requirements
        .iter()
        .filter_map(|requirement| present_field(requirement))
    {
        if !event.fields.contains_key(required_name) || declared.contains(required_name) {
            continue;
        }
        diagnostics.push(Diagnostic {
            code: "E2406",
            message: format!(
                "publication of `{event_name}` is missing required field `{required_name}`"
            ),
            span,
        });
    }
    let Some(module) = event.module.as_deref() else {
        return;
    };
    if event.requirements.is_empty() {
        return;
    }
    // A missing `present(...)` field is E2406 above; an empty one is still
    // evaluated, so `present(d)` catches `d: ""` too.
    let checked = event
        .requirements
        .iter()
        .filter(|requirement| match present_field(requirement) {
            Some(field) => declared.contains(field),
            None => true,
        })
        .cloned()
        .collect::<Vec<_>>();
    let context_fields = literal_fields(fields);
    if let Outcome::Violated(requirement) =
        requirements::evaluate(&checked, &context_fields, module, context.graph)
    {
        diagnostics.push(Diagnostic {
            code: "E2409",
            message: format!(
                "event `{event_name}` does not satisfy requirement `{requirement}` from module `{module}`"
            ),
            span: requirement_span(&requirement, fields, span),
        });
    }
}

/// The field a `present(<field>)` requirement names, if it is that shape.
fn present_field(requirement: &str) -> Option<&str> {
    requirement
        .strip_prefix("present(")
        .and_then(|name| name.strip_suffix(')'))
}

/// A constructor's literal-looking fields as requirement inputs. A computed
/// field is simply absent, so a requirement that reads it is not evaluated.
fn literal_fields(fields: &[(Spanned<String>, Expr)]) -> BTreeMap<String, Literal> {
    fields
        .iter()
        .filter_map(|(name, value)| {
            requirements::literal_field(value).map(|literal| (name.value.clone(), literal))
        })
        .collect()
}

/// Point at a constructor field the requirement names, when it names one.
fn requirement_span(requirement: &str, fields: &[(Spanned<String>, Expr)], fallback: Span) -> Span {
    let names = requirements::identifiers(requirement);
    fields
        .iter()
        .find(|(field, _)| names.contains(&field.value))
        .map_or(fallback, |(field, _)| field.span)
}

fn read_only_field(field: &str) -> Option<&'static str> {
    READ_ONLY_FIELDS
        .contains(&field)
        .then(|| read_only_reason(field))
}

/// The event declaration the program can see. `None` when nothing declares the
/// name, so an unknown event keeps the permissive historical behaviour. A
/// program's own declaration shadows an imported module's.
fn visible_event(
    event_type: &str,
    program: &Program,
    graph: &ResolvedModuleGraph,
) -> Option<VisibleEvent> {
    for item in &program.ast.items {
        if let Item::Event(event) = item
            && event.name.value == event_type
        {
            return Some(program_event(event));
        }
    }
    for module in graph.modules.values() {
        let Some(event) = module
            .descriptor
            .events
            .iter()
            .find(|event| event.name == event_type)
        else {
            continue;
        };
        return Some(VisibleEvent {
            fields: event
                .fields
                .iter()
                .map(|field| (field.name.clone(), field.type_name.clone()))
                .collect(),
            // `tags: List<Tag>` is NIP-01's free-form tag list: every author
            // field is a legitimate tag, so there is no closed set to reject.
            open: event.tags_type.as_deref() == Some("List<Tag>"),
            requirements: event.requirements.clone(),
            module: Some(module.descriptor.id.name.clone()),
        });
    }
    None
}

fn program_event(event: &EventDeclaration) -> VisibleEvent {
    let open = event.fields.iter().any(|field| {
        field.name.value == "tags"
            && field.type_ref.name == "List"
            && field
                .type_ref
                .arguments
                .first()
                .is_some_and(|argument| argument.name == "Tag")
    });
    VisibleEvent {
        fields: event
            .fields
            .iter()
            .map(|field| (field.name.value.clone(), field.type_ref.name.clone()))
            .collect(),
        open,
        requirements: Vec::new(),
        module: None,
    }
}

/// The declared tag named `tag_type`, with the module that declares it.
fn visible_tag<'a>(
    tag_type: &str,
    graph: &'a ResolvedModuleGraph,
) -> Option<(&'a str, &'a TagDefinition)> {
    graph.modules.values().find_map(|module| {
        module
            .descriptor
            .tags
            .iter()
            .find(|tag| tag.name == tag_type)
            .map(|tag| (module.descriptor.id.name.as_str(), tag))
    })
}

/// The field names a declared tag accepts in a tag record.
fn tag_slot_names(tag: &TagDefinition) -> BTreeSet<String> {
    tag.slots
        .iter()
        .filter_map(|slot| match slot {
            TagSlot::Field { name, .. } => Some(name.clone()),
            TagSlot::Literal { .. } => None,
        })
        .collect()
}

fn field_list(fields: &BTreeSet<String>) -> String {
    fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every `on` handler in the program, including those nested in functions.
fn collect_handlers<'a>(items: &'a [Item], out: &mut Vec<(&'a Expr, &'a [Item])>) {
    for item in items {
        match item {
            Item::Function(function) => collect_handlers(&function.body, out),
            Item::Statement(statement) => collect_statement_handlers(&statement.value, out),
            _ => {}
        }
    }
}

fn collect_statement_handlers<'a>(
    statement: &'a StatementKind,
    out: &mut Vec<(&'a Expr, &'a [Item])>,
) {
    match statement {
        StatementKind::On { source, body, .. } => {
            out.push((source, body));
            collect_handlers(body, out);
        }
        StatementKind::For { body, .. }
        | StatementKind::Once { body, .. }
        | StatementKind::Every { body, .. }
        | StatementKind::At { body, .. } => collect_handlers(body, out),
        StatementKind::If {
            then_body,
            else_body,
            ..
        } => {
            collect_handlers(then_body, out);
            collect_handlers(else_body, out);
        }
        _ => {}
    }
}

/// Whether the body rebinds the name `event`, in which case `event.x` no longer
/// means the delivered event and is left alone.
fn declares_event(items: &[Item]) -> bool {
    items.iter().any(|item| match item {
        Item::Let(declaration) => declaration.name.value == "event",
        Item::Statement(statement) => match &statement.value {
            StatementKind::For { binding, body, .. } => {
                binding.value == "event" || declares_event(body)
            }
            StatementKind::If {
                then_body,
                else_body,
                ..
            } => declares_event(then_body) || declares_event(else_body),
            StatementKind::On { body, .. }
            | StatementKind::Once { body, .. }
            | StatementKind::Every { body, .. }
            | StatementKind::At { body, .. } => declares_event(body),
            _ => false,
        },
        _ => false,
    })
}

/// Field name to type for `event_type`: the signed event's own fields, overridden
/// by what the program or a module declares for the type. `None` if nothing
/// defines the type.
fn event_fields(
    event_type: &str,
    program: &Program,
    graph: &ResolvedModuleGraph,
) -> Option<BTreeMap<String, String>> {
    let mut defined: Option<BTreeMap<String, String>> = None;
    for item in &program.ast.items {
        if let Item::Event(event) = item
            && event.name.value == event_type
        {
            defined = Some(
                event
                    .fields
                    .iter()
                    .map(|field| (field.name.value.clone(), field.type_ref.name.clone()))
                    .collect(),
            );
        }
    }
    // A program's own declaration shadows imported modules, the same rule
    // `CheckedProgram::events` and publication lowering already follow.
    if defined.is_none() {
        for module in graph.modules.values() {
            let descriptor = &module.descriptor;
            if let Some(event) = descriptor
                .events
                .iter()
                .find(|event| event.name == event_type)
            {
                let mut fields: BTreeMap<String, String> = event
                    .fields
                    .iter()
                    .map(|field| (field.name.clone(), field.type_name.clone()))
                    .collect();
                fields.insert("content".to_owned(), event.content_type.clone());
                if let Some(tags) = &event.tags_type {
                    fields.insert("tags".to_owned(), tags.clone());
                }
                defined = Some(fields);
            }
            if defined.is_none()
                && let Some(TypeDefinition::Record { fields, .. }) = descriptor
                    .types
                    .iter()
                    .find(|definition| definition.name() == event_type)
            {
                defined = Some(
                    fields
                        .iter()
                        .map(|field| (field.name.clone(), field.type_name.clone()))
                        .collect(),
                );
            }
        }
    }
    let defined = defined?;
    let mut all: BTreeMap<String, String> = COMMON_FIELDS
        .iter()
        .map(|(name, ty)| ((*name).to_owned(), (*ty).to_owned()))
        .collect();
    all.extend(defined);
    Some(all)
}

struct HandlerChecker<'a> {
    event_type: &'a str,
    fields: &'a BTreeMap<String, String>,
    program: &'a Program,
    graph: &'a ResolvedModuleGraph,
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl HandlerChecker<'_> {
    fn declares_key(&self, name: &str) -> bool {
        self.program
            .ast
            .items
            .iter()
            .any(|item| matches!(item, Item::Key(key) if key.name.value == name))
    }

    fn error(&mut self, code: &'static str, span: Span, message: String) {
        self.diagnostics.push(Diagnostic {
            code,
            message,
            span,
        });
    }

    /// Statements in order, so a `let` types the names after it.
    fn block(&mut self, items: &[Item], env: &mut BTreeMap<String, String>) {
        for item in items {
            match item {
                Item::Let(declaration) => {
                    self.expression(&declaration.value, env);
                    let known = declaration
                        .type_annotation
                        .as_ref()
                        .map(|annotation| annotation.name.clone())
                        .or_else(|| self.infer(&declaration.value, env));
                    match known {
                        Some(ty) => env.insert(declaration.name.value.clone(), ty),
                        None => env.remove(&declaration.name.value),
                    };
                }
                Item::Statement(statement) => self.statement(&statement.value, env),
                _ => {}
            }
        }
    }

    fn statement(&mut self, statement: &StatementKind, env: &mut BTreeMap<String, String>) {
        match statement {
            StatementKind::Expression(value) | StatementKind::Return(Some(value)) => {
                self.expression(value, env);
            }
            StatementKind::For { value, body, .. } => {
                self.expression(value, env);
                self.block(body, &mut env.clone());
            }
            StatementKind::If {
                condition,
                then_body,
                else_body,
            } => {
                self.expression(condition, env);
                self.block(then_body, &mut env.clone());
                self.block(else_body, &mut env.clone());
            }
            StatementKind::Send { value, signer } => {
                self.expression(value, env);
                if let Some(signer) = signer {
                    self.expression(signer, env);
                }
            }
            StatementKind::On { body, .. }
            | StatementKind::Once { body, .. }
            | StatementKind::Every { body, .. }
            | StatementKind::At { body, .. } => self.block(body, &mut env.clone()),
            StatementKind::Return(None) => {}
        }
    }

    fn expression(&mut self, expression: &Expr, env: &BTreeMap<String, String>) {
        match &expression.value {
            ExprKind::Member { value, name } => {
                if matches!(&value.value, ExprKind::Identifier(base) if base == "event")
                    && !self.fields.contains_key(&name.value)
                {
                    self.unknown_field(&name.value, name.span);
                }
                self.expression(value, env);
            }
            ExprKind::Call { callee, arguments } => {
                self.expression(callee, env);
                for argument in arguments {
                    self.expression(argument, env);
                }
                self.check_arguments(callee, arguments, env);
            }
            ExprKind::Match { value, arms } => {
                self.expression(value, env);
                let on_event =
                    matches!(&value.value, ExprKind::Identifier(name) if name == "event");
                for arm in arms {
                    if on_event {
                        self.record_pattern(&arm.pattern.value, arm.pattern.span);
                    }
                    if let Some(guard) = &arm.guard {
                        self.expression(guard, env);
                    }
                    self.expression(&arm.value, env);
                }
            }
            ExprKind::Index { value, index } => {
                self.expression(value, env);
                self.expression(index, env);
            }
            ExprKind::Unary { value, .. } | ExprKind::Propagate(value) => {
                self.expression(value, env);
            }
            ExprKind::Binary { left, right, .. }
            | ExprKind::Assign {
                target: left,
                value: right,
            } => {
                self.expression(left, env);
                self.expression(right, env);
            }
            ExprKind::List(items) => {
                for item in items {
                    self.expression(item, env);
                }
            }
            ExprKind::Record(fields) | ExprKind::Construct { fields, .. } => {
                for (_, value) in fields {
                    self.expression(value, env);
                }
            }
            _ => {}
        }
    }

    /// A record pattern on the event that names the event's own type must name
    /// only fields it has.
    fn record_pattern(&mut self, pattern: &PatternKind, span: Span) {
        if let PatternKind::Record { name, fields } = pattern
            && name == self.event_type
        {
            for (field, _) in fields {
                if !self.fields.contains_key(field) {
                    self.unknown_field(field, span);
                }
            }
        }
    }

    fn unknown_field(&mut self, field: &str, span: Span) {
        let names: Vec<&str> = self.fields.keys().map(String::as_str).collect();
        let message = format!(
            "`event` (a `{}`) has no field `{field}`; its fields are: {}",
            self.event_type,
            names.join(", ")
        );
        self.error("E1101", span, message);
    }

    /// The type of an expression when it is certain; `None` when unknown, which
    /// is never an error.
    fn infer(&self, expression: &Expr, env: &BTreeMap<String, String>) -> Option<String> {
        match &expression.value {
            ExprKind::Integer(_) => Some("Int".to_owned()),
            ExprKind::Text(_) => Some("Text".to_owned()),
            ExprKind::Bool(_) => Some("Bool".to_owned()),
            ExprKind::Identifier(name) => env
                .get(name)
                .cloned()
                // `me` is the program's principal.
                .or_else(|| (name == "me").then(|| "PubKey".to_owned()))
                .or_else(|| self.declares_key(name).then(|| "DerivedKey".to_owned())),
            ExprKind::Member { value, name } if matches!(&value.value, ExprKind::Identifier(base) if base == "event") => {
                self.fields.get(&name.value).cloned()
            }
            _ => None,
        }
    }

    /// `module.operation(args)`: an argument whose type is known must match the
    /// declared parameter, when both are plain scalar types. The language treats
    /// `PubKey` and `Text` as distinct nominal types.
    fn check_arguments(
        &mut self,
        callee: &Expr,
        arguments: &[Expr],
        env: &BTreeMap<String, String>,
    ) {
        let ExprKind::Member { value, name } = &callee.value else {
            return;
        };
        let ExprKind::Identifier(module) = &value.value else {
            return;
        };
        if !self
            .program
            .imports
            .iter()
            .any(|import| &import.path == module)
        {
            return;
        }
        let Some(registered) = self.graph.modules.get(module) else {
            return;
        };
        // `function` declarations (RFC 0002 §3 fold queries) are checked the
        // same way as `operation`s: only their permission requirement (or
        // lack of one) differs.
        let Some(parameters) = registered
            .descriptor
            .operations
            .iter()
            .find(|operation| operation.name == name.value)
            .map(|operation| &operation.parameters)
            .or_else(|| {
                registered
                    .descriptor
                    .functions
                    .iter()
                    .find(|function| function.name == name.value)
                    .map(|function| &function.parameters)
            })
        else {
            return;
        };
        let parameters: Vec<(String, String)> = parameters
            .iter()
            .map(|parameter| (parameter.name.clone(), parameter.type_name.clone()))
            .collect();
        for (argument, (parameter, expected)) in arguments.iter().zip(parameters) {
            let Some(found) = self.infer(argument, env) else {
                continue;
            };
            if found != expected
                && SCALARS.contains(&found.as_str())
                && SCALARS.contains(&expected.as_str())
            {
                self.error(
                    "E1001",
                    argument.span,
                    format!(
                        "`{module}.{}` expects `{expected}` for `{parameter}`, found `{found}`",
                        name.value
                    ),
                );
            }
        }
    }
}
