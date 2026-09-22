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

use std::collections::BTreeMap;

use nscript_modules::{ResolvedModuleGraph, TypeDefinition};
use nscript_syntax::ast::{Expr, ExprKind, Item, PatternKind, StatementKind};
use nscript_syntax::{Diagnostic, Program, Span};

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
        for definition in &descriptor.types {
            if let TypeDefinition::Record { name, fields } = definition
                && name == event_type
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
        let Some(operation) = self.graph.modules.get(module).and_then(|registered| {
            registered
                .descriptor
                .operations
                .iter()
                .find(|operation| operation.name == name.value)
        }) else {
            return;
        };
        let parameters: Vec<(String, String)> = operation
            .parameters
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
