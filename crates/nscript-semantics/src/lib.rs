//! Static policy checks for `NScript` programs.

use std::collections::{BTreeMap, BTreeSet};

use nscript_modules::ResolvedModuleGraph;
use nscript_syntax::{
    Diagnostic, Program, RuntimeProfile, Span,
    ast::{Expr, ExprKind, Item, PatternKind, Permission, StatementKind, TypeRef},
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Effect {
    Relay,
    Sign,
    Storage,
    Clock,
    Log,
    Http,
    SecretKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedPublication {
    pub event: String,
    pub content: Option<String>,
    pub signer: String,
    pub relayset: String,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckedArgument {
    Text(String),
    Integer(i64),
    PubKey(String),
    Record {
        name: String,
        fields: Vec<(String, CheckedArgument)>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedOperationCall {
    pub module: String,
    pub operation: String,
    pub arguments: Vec<CheckedArgument>,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckedScheduleKind {
    Every,
    At,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedSchedule {
    pub kind: CheckedScheduleKind,
    pub value: u64,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedHandler {
    pub event_type: String,
    pub has_predicate: bool,
    pub author: Option<String>,
    pub tag_equals: Vec<(String, String)>,
    pub body_items: usize,
    pub body: Vec<Item>,
    pub span: Span,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckedProgram {
    pub effects: BTreeSet<Effect>,
    pub publications: Vec<CheckedPublication>,
    pub operation_calls: Vec<CheckedOperationCall>,
    pub schedules: Vec<CheckedSchedule>,
    pub handlers: Vec<CheckedHandler>,
}

const HARDENED_FORBIDDEN: &[&str] = &[
    "SecretKey",
    "Nsec",
    "secret_key",
    "filesystem",
    "process",
    "shell",
    "raw_socket",
    "native_plugin",
];

#[must_use]
pub fn analyze(program: &Program) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    if program.profile == RuntimeProfile::HardenedAgent {
        for (name, span) in &program.identifiers {
            if HARDENED_FORBIDDEN.contains(&name.as_str()) {
                diagnostics.push(Diagnostic {
                    code: "E5001",
                    message: format!("`{name}` is forbidden by the hardened-agent runtime profile"),
                    span: *span,
                });
            }
        }
    }

    if let Some((name, span)) = &program.defaults.signer
        && !program.signers.contains(name)
    {
        diagnostics.push(Diagnostic {
            code: "E1101",
            message: format!("default signer `{name}` is not declared"),
            span: *span,
        });
    }
    if let Some((name, span)) = &program.defaults.relays
        && !program.relaysets.contains(name)
    {
        diagnostics.push(Diagnostic {
            code: "E1101",
            message: format!("default relay set `{name}` is not declared"),
            span: *span,
        });
    }

    for publish in &program.publishes {
        if publish.requires_signer && !publish.explicit_signer && program.defaults.signer.is_none()
        {
            diagnostics.push(Diagnostic {
                code: "E2203",
                message: "unsigned publication has no declared default signer".to_owned(),
                span: publish.span,
            });
        }
        if !publish.explicit_relays && program.defaults.relays.is_none() {
            diagnostics.push(Diagnostic {
                code: "E2204",
                message: "publication has no declared default relay set".to_owned(),
                span: publish.span,
            });
        }
    }
    let (_, typed_diagnostics) = check(program);
    diagnostics.extend(typed_diagnostics);

    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    diagnostics.dedup_by(|left, right| {
        left.code == right.code && left.span == right.span && left.message == right.message
    });
    diagnostics
}

#[must_use]
pub fn analyze_with_modules(program: &Program, graph: &ResolvedModuleGraph) -> Vec<Diagnostic> {
    let mut diagnostics = analyze(program);
    diagnostics.extend(validate_module_symbols(program, graph));
    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    diagnostics
}

fn validate_module_symbols(program: &Program, graph: &ResolvedModuleGraph) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let mut exports = BTreeMap::<String, String>::new();
    for module in graph.modules.values() {
        let descriptor = &module.descriptor;
        if program.profile == RuntimeProfile::HardenedAgent {
            for operation in &descriptor.operations {
                for effect in &operation.effects {
                    if matches!(
                        effect.to_ascii_lowercase().as_str(),
                        "filesystem"
                            | "process"
                            | "shell"
                            | "raw_socket"
                            | "native_plugin"
                            | "secret_key"
                    ) {
                        diagnostics.push(Diagnostic {
                            code: "E5001",
                            message: format!(
                                "module `{}` transitively requires forbidden effect `{effect}`",
                                descriptor.id.name
                            ),
                            span: program
                                .imports
                                .first()
                                .map_or_else(Span::default, |import| import.span),
                        });
                    }
                }
            }
        }
        let names = descriptor
            .types
            .iter()
            .map(nscript_modules::TypeDefinition::name)
            .chain(descriptor.events.iter().map(|item| item.name.as_str()))
            .chain(descriptor.tags.iter().map(|item| item.name.as_str()))
            .chain(descriptor.errors.iter().map(|item| item.name.as_str()))
            .chain(descriptor.functions.iter().map(|item| item.name.as_str()))
            .chain(descriptor.operations.iter().map(|item| item.name.as_str()));
        for name in names {
            if let Some(first) = exports.insert(name.to_owned(), descriptor.id.name.clone())
                && first != descriptor.id.name
            {
                diagnostics.push(Diagnostic {
                    code: "E4003",
                    message: format!(
                        "ambiguous export `{name}` is provided by `{first}` and `{}`",
                        descriptor.id.name
                    ),
                    span: program
                        .imports
                        .first()
                        .map_or(Span::default(), |item| item.span),
                });
            }
        }
    }
    let mut known = core_types();
    known.extend(exports.keys().cloned());
    for item in &program.ast.items {
        if let Item::Event(event) = item {
            known.insert(event.name.value.clone());
        }
    }
    for item in &program.ast.items {
        validate_item_types(item, &known, &mut diagnostics);
    }
    validate_module_calls(program, graph, &mut diagnostics);
    diagnostics
}

/// What call validation needs to know about the program's modules.
struct CallContext {
    /// `module.operation` to its declarations, for imported modules.
    calls: BTreeMap<String, Vec<ModuleCall>>,
    /// Modules the program imports with `use`.
    imported: BTreeSet<String>,
    /// Every module the registry knows, imported or not.
    known: BTreeSet<String>,
    /// Imported modules that resolved. An import that failed to resolve has
    /// already been reported (`E4002`); its calls are not reported again.
    resolved: BTreeSet<String>,
    /// Names the program declares itself, which shadow module names.
    locals: BTreeSet<String>,
}

#[derive(Clone)]
struct ModuleCall {
    module: String,
    operation: String,
    arity: usize,
    permission: Option<String>,
}

fn validate_module_calls(
    program: &Program,
    graph: &ResolvedModuleGraph,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let imported = program
        .imports
        .iter()
        .map(|item| item.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut calls = BTreeMap::<String, Vec<ModuleCall>>::new();
    for module_name in imported {
        let Some(module) = graph.modules.get(module_name) else {
            continue;
        };
        for operation in &module.descriptor.operations {
            let call = ModuleCall {
                module: module_name.to_owned(),
                operation: operation.name.clone(),
                arity: operation.parameters.len(),
                permission: Some(operation.permission.clone()),
            };
            calls
                .entry(operation.name.clone())
                .or_default()
                .push(call.clone());
            calls
                .entry(format!("{module_name}.{}", operation.name))
                .or_default()
                .push(call);
        }
        for function in &module.descriptor.functions {
            let call = ModuleCall {
                module: module_name.to_owned(),
                operation: function.name.clone(),
                arity: function.parameters.len(),
                permission: None,
            };
            calls
                .entry(function.name.clone())
                .or_default()
                .push(call.clone());
            calls
                .entry(format!("{module_name}.{}", function.name))
                .or_default()
                .push(call);
        }
    }
    let permissions = program_permissions(program);
    let context = CallContext {
        calls,
        imported: program
            .imports
            .iter()
            .map(|item| item.path.clone())
            .collect(),
        known: graph.known.clone(),
        resolved: graph.modules.keys().cloned().collect(),
        locals: program_locals(program),
    };
    for item in &program.ast.items {
        validate_item_calls(item, &context, &permissions, diagnostics);
    }
}

/// Names the program itself declares at top level. A declaration named like a
/// module shadows it, so `let nip44 = 1` is not a call into the module.
fn program_locals(program: &Program) -> BTreeSet<String> {
    program
        .ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Let(declaration) => Some(declaration.name.value.clone()),
            Item::Function(function) => Some(function.name.value.clone()),
            Item::Stream { name, .. } => Some(name.value.clone()),
            Item::Signer(declaration) | Item::Relay(declaration) | Item::RelaySet(declaration) => {
                Some(declaration.name.value.clone())
            }
            _ => None,
        })
        .collect()
}

fn program_permissions(program: &Program) -> BTreeSet<String> {
    let mut permissions = BTreeSet::new();
    for item in &program.ast.items {
        if let Item::Permissions(block) = item {
            for permission in &block.value {
                match permission {
                    Permission::Typed { operation, .. } | Permission::Named { operation, .. } => {
                        permissions.insert(operation.value.clone());
                    }
                    Permission::Http(_) => {
                        permissions.insert("http".to_owned());
                    }
                    _ => {}
                }
            }
        }
    }
    permissions
}

fn validate_item_calls(
    item: &Item,
    calls: &CallContext,
    permissions: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match item {
        Item::Let(declaration) => {
            validate_expr_calls(&declaration.value, calls, permissions, diagnostics);
        }
        Item::Function(function) => {
            for nested in &function.body {
                validate_item_calls(nested, calls, permissions, diagnostics);
            }
        }
        Item::Stream { value, .. } => validate_expr_calls(value, calls, permissions, diagnostics),
        Item::Statement(statement) => {
            validate_statement_calls(&statement.value, calls, permissions, diagnostics);
        }
        _ => {}
    }
}

fn validate_statement_calls(
    statement: &StatementKind,
    calls: &CallContext,
    permissions: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match statement {
        StatementKind::Expression(value) | StatementKind::Return(Some(value)) => {
            validate_expr_calls(value, calls, permissions, diagnostics);
        }
        StatementKind::For { value, body, .. } => {
            validate_expr_calls(value, calls, permissions, diagnostics);
            for nested in body {
                validate_item_calls(nested, calls, permissions, diagnostics);
            }
        }
        StatementKind::If {
            condition,
            then_body,
            else_body,
        } => {
            validate_expr_calls(condition, calls, permissions, diagnostics);
            for nested in then_body {
                validate_item_calls(nested, calls, permissions, diagnostics);
            }
            for nested in else_body {
                validate_item_calls(nested, calls, permissions, diagnostics);
            }
        }
        StatementKind::On {
            source,
            predicate,
            body,
        } => {
            validate_expr_calls(source, calls, permissions, diagnostics);
            if let Some(predicate) = predicate {
                validate_expr_calls(predicate, calls, permissions, diagnostics);
            }
            for nested in body {
                validate_item_calls(nested, calls, permissions, diagnostics);
            }
        }
        StatementKind::Once { key, body } => {
            validate_expr_calls(key, calls, permissions, diagnostics);
            for nested in body {
                validate_item_calls(nested, calls, permissions, diagnostics);
            }
        }
        StatementKind::Every { duration, body }
        | StatementKind::At {
            schedule: duration,
            body,
        } => {
            validate_expr_calls(duration, calls, permissions, diagnostics);
            for nested in body {
                validate_item_calls(nested, calls, permissions, diagnostics);
            }
        }
        StatementKind::Send { value, signer } => {
            validate_expr_calls(value, calls, permissions, diagnostics);
            if let Some(signer) = signer {
                validate_expr_calls(signer, calls, permissions, diagnostics);
            }
        }
        StatementKind::Return(None) => {}
    }
}

/// A call the checker cannot resolve is not a call it can check, so it must not
/// pass silently: a program that calls `concord04.kick_member` without
/// `use concord04` would otherwise be checked against no permissions at all.
fn report_unresolved_module_call(
    path: &str,
    span: Span,
    calls: &CallContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some((module, operation)) = path.split_once('.') else {
        return;
    };
    // Only `module.operation`; deeper paths are member chains on values.
    if operation.contains('.') || calls.locals.contains(module) {
        return;
    }
    if calls.imported.contains(module) {
        if calls.resolved.contains(module) && !calls.calls.contains_key(path) {
            diagnostics.push(Diagnostic {
                code: "E1101",
                message: format!("module `{module}` has no operation `{operation}`"),
                span,
            });
        }
    } else if calls.known.contains(module) {
        diagnostics.push(Diagnostic {
            code: "E1101",
            message: format!("module `{module}` is not imported; add `use {module}`"),
            span,
        });
    }
}

#[allow(clippy::too_many_lines)]
fn validate_expr_calls(
    expression: &Expr,
    calls: &CallContext,
    permissions: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let ExprKind::Call { callee, .. } = &expression.value
        && let Some(name) = expression_path(callee)
    {
        report_unresolved_module_call(&name, callee.span, calls, diagnostics);
    }
    if let ExprKind::Call { callee, arguments } = &expression.value
        && let Some(name) = expression_path(callee)
        && let Some(candidates) = calls.calls.get(&name)
    {
        if candidates.len() > 1 {
            diagnostics.push(Diagnostic {
                code: "E4003",
                message: format!("ambiguous module call `{name}`"),
                span: callee.span,
            });
        } else if let Some(call) = candidates.first() {
            if arguments.len() != call.arity {
                diagnostics.push(Diagnostic {
                    code: "E1102",
                    message: format!(
                        "{}.{}` expects {} arguments, found {}",
                        call.module,
                        call.operation,
                        call.arity,
                        arguments.len()
                    ),
                    span: expression.span,
                });
            }
            if let Some(permission) = &call.permission
                && !permissions.contains(permission)
            {
                diagnostics.push(Diagnostic {
                    code: "E3001",
                    message: format!("operation requires `{permission}` permission"),
                    span: expression.span,
                });
            }
        }
    }
    match &expression.value {
        ExprKind::Call { callee, arguments } => {
            validate_expr_calls(callee, calls, permissions, diagnostics);
            for argument in arguments {
                validate_expr_calls(argument, calls, permissions, diagnostics);
            }
        }
        ExprKind::Member { value, .. }
        | ExprKind::Propagate(value)
        | ExprKind::Unary { value, .. }
        | ExprKind::Sign { value, .. } => {
            validate_expr_calls(value, calls, permissions, diagnostics);
        }
        ExprKind::Publish {
            value,
            relays,
            signer,
        } => {
            validate_expr_calls(value, calls, permissions, diagnostics);
            if let Some(relays) = relays {
                validate_expr_calls(relays, calls, permissions, diagnostics);
            }
            if let Some(signer) = signer {
                validate_expr_calls(signer, calls, permissions, diagnostics);
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
            validate_expr_calls(left, calls, permissions, diagnostics);
            validate_expr_calls(right, calls, permissions, diagnostics);
        }
        ExprKind::List(values) => {
            for value in values {
                validate_expr_calls(value, calls, permissions, diagnostics);
            }
        }
        ExprKind::Record(values) | ExprKind::Construct { fields: values, .. } => {
            for (_, value) in values {
                validate_expr_calls(value, calls, permissions, diagnostics);
            }
        }
        ExprKind::Select(select) => {
            if let Some(predicate) = &select.predicate {
                validate_expr_calls(predicate, calls, permissions, diagnostics);
            }
            if let Some(since) = &select.since {
                validate_expr_calls(since, calls, permissions, diagnostics);
            }
            if let Some(until) = &select.until {
                validate_expr_calls(until, calls, permissions, diagnostics);
            }
            if let Some(relays) = &select.relays {
                validate_expr_calls(relays, calls, permissions, diagnostics);
            }
        }
        ExprKind::Fetch { url, .. } => {
            validate_expr_calls(url, calls, permissions, diagnostics);
        }
        ExprKind::Latest {
            relays: Some(relays),
            ..
        } => validate_expr_calls(relays, calls, permissions, diagnostics),
        ExprKind::Match { value, arms } => {
            validate_expr_calls(value, calls, permissions, diagnostics);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    validate_expr_calls(guard, calls, permissions, diagnostics);
                }
                validate_expr_calls(&arm.value, calls, permissions, diagnostics);
            }
        }
        _ => {}
    }
}

/// Whether a pattern compares against a literal anywhere inside it, and so
/// matches only some values of its type.
fn tests_a_literal(pattern: &PatternKind) -> bool {
    match pattern {
        PatternKind::Literal(_) => true,
        PatternKind::Variant { values, .. } => {
            values.iter().any(|value| tests_a_literal(&value.value))
        }
        PatternKind::Record { fields, .. } => fields
            .iter()
            .any(|(_, sub)| sub.as_ref().is_some_and(|sub| tests_a_literal(&sub.value))),
        PatternKind::Wildcard | PatternKind::Binding(_) => false,
    }
}

fn expression_path(expression: &Expr) -> Option<String> {
    match &expression.value {
        ExprKind::Identifier(name) => Some(name.clone()),
        ExprKind::Member { value, name } => {
            Some(format!("{}.{}", expression_path(value)?, name.value))
        }
        _ => None,
    }
}

fn core_types() -> BTreeSet<String> {
    [
        "Bool",
        "Int",
        "Decimal",
        "Text",
        "Bytes",
        "Duration",
        "Percentage",
        "Unit",
        "Never",
        "List",
        "Set",
        "Map",
        "Option",
        "Result",
        "PubKey",
        "EventId",
        "Signature",
        "RelayUrl",
        "Timestamp",
        "Kind",
        "Nprofile",
        "Nevent",
        "Naddr",
        "Nsec",
        "Signer",
        "SecretKey",
        "Tag",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn validate_item_types(item: &Item, known: &BTreeSet<String>, diagnostics: &mut Vec<Diagnostic>) {
    match item {
        Item::Let(item) => {
            if let Some(type_ref) = &item.type_annotation {
                validate_type(type_ref, known, diagnostics);
            }
        }
        Item::Function(item) => {
            for parameter in &item.parameters {
                validate_type(&parameter.type_ref, known, diagnostics);
            }
            if let Some(type_ref) = &item.return_type {
                validate_type(type_ref, known, diagnostics);
            }
            for nested in &item.body {
                validate_item_types(nested, known, diagnostics);
            }
        }
        Item::Event(item) => {
            for field in &item.fields {
                validate_type(&field.type_ref, known, diagnostics);
            }
        }
        Item::Store(item) => {
            if let Some(type_ref) = &item.key_type {
                validate_type(type_ref, known, diagnostics);
            }
            validate_type(&item.value_type, known, diagnostics);
        }
        Item::Permissions(block) => {
            for permission in &block.value {
                match permission {
                    Permission::Read { event, .. }
                    | Permission::Publish { event, .. }
                    | Permission::Sign { event, .. }
                    | Permission::Typed { target: event, .. } => {
                        validate_type(event, known, diagnostics);
                    }
                    Permission::Named { .. } | Permission::Http(_) => {}
                }
            }
        }
        _ => {}
    }
}

fn validate_type(type_ref: &TypeRef, known: &BTreeSet<String>, diagnostics: &mut Vec<Diagnostic>) {
    if !known.contains(&type_ref.name) {
        diagnostics.push(Diagnostic {
            code: "E1101",
            message: format!("unknown type `{}`", type_ref.name),
            span: type_ref.span,
        });
    }
    for argument in &type_ref.arguments {
        validate_type(argument, known, diagnostics);
    }
}

fn schedule_value(expression: &Expr, every: bool) -> Option<u64> {
    match &expression.value {
        ExprKind::Duration { value, unit } if every => {
            let multiplier = match unit.as_str() {
                "s" => 1,
                "m" => 60,
                "h" => 60 * 60,
                "d" => 24 * 60 * 60,
                _ => return None,
            };
            value.checked_mul(multiplier)
        }
        ExprKind::Integer(value) if !every => (*value).try_into().ok(),
        _ => None,
    }
}

fn handler_event_type(expression: &Expr) -> Option<String> {
    match &expression.value {
        ExprKind::Identifier(name) => Some(name.clone()),
        ExprKind::Construct { name, .. } => Some(name.value.clone()),
        _ => None,
    }
}

fn handler_predicate_filters(expression: Option<&Expr>) -> (Option<String>, Vec<(String, String)>) {
    let Some(expression) = expression else {
        return (None, Vec::new());
    };
    let ExprKind::Binary {
        operator,
        left,
        right,
    } = &expression.value
    else {
        return (None, Vec::new());
    };
    match (operator.as_str(), &left.value, &right.value) {
        ("==", ExprKind::Identifier(name), ExprKind::Identifier(value)) if name == "author" => {
            (Some(value.clone()), Vec::new())
        }
        ("contains", ExprKind::Member { value, name }, ExprKind::Text(text)) if matches!(&value.value, ExprKind::Identifier(base) if base == "tags") => {
            (None, vec![(name.value.clone(), text.clone())])
        }
        _ => (None, Vec::new()),
    }
}

#[must_use]
pub fn check(program: &Program) -> (Option<CheckedProgram>, Vec<Diagnostic>) {
    let mut checker = Checker::new(program);
    checker.check_items(&program.ast.items, &mut BTreeMap::new());
    let result = checker.diagnostics.is_empty().then_some(CheckedProgram {
        effects: checker.effects,
        publications: checker.publications,
        operation_calls: checker.operation_calls,
        schedules: checker.schedules,
        handlers: checker.handlers,
    });
    (result, checker.diagnostics)
}

#[derive(Default)]
struct PermissionSet {
    operations: BTreeSet<String>,
    reads: BTreeSet<(String, Option<String>)>,
    publishes: BTreeSet<(String, Option<String>)>,
    signs: BTreeSet<(String, Option<String>)>,
}

struct Checker<'a> {
    program: &'a Program,
    permissions: PermissionSet,
    defaults_signer: Option<String>,
    defaults_relays: Option<String>,
    effects: BTreeSet<Effect>,
    publications: Vec<CheckedPublication>,
    operation_calls: Vec<CheckedOperationCall>,
    schedules: Vec<CheckedSchedule>,
    handlers: Vec<CheckedHandler>,
    diagnostics: Vec<Diagnostic>,
    event_bindings: BTreeSet<String>,
}

impl<'a> Checker<'a> {
    fn new(program: &'a Program) -> Self {
        let mut checker = Self {
            program,
            permissions: PermissionSet::default(),
            defaults_signer: program.defaults.signer.as_ref().map(|item| item.0.clone()),
            defaults_relays: program.defaults.relays.as_ref().map(|item| item.0.clone()),
            effects: BTreeSet::new(),
            publications: Vec::new(),
            operation_calls: Vec::new(),
            schedules: Vec::new(),
            handlers: Vec::new(),
            diagnostics: Vec::new(),
            event_bindings: BTreeSet::new(),
        };
        checker.collect_permissions();
        checker
    }

    fn collect_permissions(&mut self) {
        for item in &self.program.ast.items {
            let Item::Permissions(block) = item else {
                continue;
            };
            for permission in &block.value {
                match permission {
                    Permission::Read { event, relayset } => {
                        self.permissions.reads.insert((
                            event.name.clone(),
                            relayset.as_ref().map(|item| item.value.clone()),
                        ));
                    }
                    Permission::Publish { event, relayset } => {
                        self.permissions.publishes.insert((
                            event.name.clone(),
                            relayset.as_ref().map(|item| item.value.clone()),
                        ));
                    }
                    Permission::Sign { event, signer } => {
                        self.permissions.signs.insert((
                            event.name.clone(),
                            signer.as_ref().map(|item| item.value.clone()),
                        ));
                    }
                    Permission::Typed { operation, .. } | Permission::Named { operation, .. } => {
                        self.permissions.operations.insert(operation.value.clone());
                    }
                    Permission::Http(_) => {
                        self.permissions.operations.insert("http".to_owned());
                    }
                }
            }
        }
    }

    fn check_items(&mut self, items: &[Item], locals: &mut BTreeMap<String, TypeRef>) {
        for item in items {
            match item {
                Item::Let(declaration) => {
                    self.check_expr(&declaration.value, locals);
                    if let Some(annotation) = &declaration.type_annotation {
                        locals.insert(declaration.name.value.clone(), annotation.clone());
                        if annotation.name == "SecretKey"
                            && !self.permissions.operations.contains("secret_key")
                        {
                            self.missing_permission(declaration.name.span, "secret_key");
                        }
                    } else if let ExprKind::Construct { name, .. } = &declaration.value.value {
                        self.event_bindings.insert(declaration.name.value.clone());
                        locals.insert(
                            declaration.name.value.clone(),
                            TypeRef {
                                name: format!("Unsigned<{}>", name.value),
                                arguments: Vec::new(),
                                span: name.span,
                            },
                        );
                    }
                }
                Item::Function(function) => self.check_function(function, locals),
                Item::Event(event) => self.check_event(event),
                Item::Stream { value, .. } => self.check_expr(value, locals),
                Item::Statement(statement) => {
                    self.check_statement(&statement.value, statement.span, locals);
                }
                _ => {}
            }
        }
    }

    fn check_function(
        &mut self,
        function: &nscript_syntax::ast::FunctionDeclaration,
        outer: &BTreeMap<String, TypeRef>,
    ) {
        let mut locals = outer.clone();
        for parameter in &function.parameters {
            locals.insert(parameter.name.value.clone(), parameter.type_ref.clone());
        }
        for item in &function.body {
            if let Item::Statement(statement) = item
                && let StatementKind::Return(Some(value)) = &statement.value
                && let (Some(expected), ExprKind::Identifier(name)) =
                    (&function.return_type, &value.value)
                && let Some(actual) = locals.get(name)
                && actual.name != expected.name
            {
                self.diagnostics.push(Diagnostic {
                    code: "E1001",
                    message: format!("expected `{}`, found `{}`", expected.name, actual.name),
                    span: value.span,
                });
            }
        }
        self.check_items(&function.body, &mut locals);
    }

    fn check_event(&mut self, event: &nscript_syntax::ast::EventDeclaration) {
        if let Some(kind) = event.kind {
            let valid = match event.mode {
                nscript_syntax::ast::EventModeSyntax::Regular => !(20_000..40_000).contains(&kind),
                nscript_syntax::ast::EventModeSyntax::Replaceable => {
                    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
                }
                nscript_syntax::ast::EventModeSyntax::Ephemeral => (20_000..30_000).contains(&kind),
                nscript_syntax::ast::EventModeSyntax::Parameterised => {
                    (30_000..40_000).contains(&kind)
                }
            };
            if !valid {
                self.diagnostics.push(Diagnostic {
                    code: "E1201",
                    message: format!("event kind {kind} is incompatible with its replacement mode"),
                    span: event.span,
                });
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn check_statement(
        &mut self,
        statement: &StatementKind,
        span: Span,
        locals: &mut BTreeMap<String, TypeRef>,
    ) {
        match statement {
            StatementKind::Expression(value) | StatementKind::Return(Some(value)) => {
                self.check_expr(value, locals);
            }
            StatementKind::For { value, body, .. } => {
                self.check_expr(value, locals);
                self.check_items(body, &mut locals.clone());
            }
            StatementKind::If {
                condition,
                then_body,
                else_body,
            } => {
                self.check_expr(condition, locals);
                self.check_items(then_body, &mut locals.clone());
                self.check_items(else_body, &mut locals.clone());
            }
            StatementKind::On {
                source,
                predicate,
                body,
            } => {
                self.effects.insert(Effect::Relay);
                self.check_expr(source, locals);
                if let Some(predicate) = predicate {
                    self.check_expr(predicate, locals);
                }
                if let Some(event_type) = handler_event_type(source) {
                    let (author, tag_equals) = handler_predicate_filters(predicate.as_ref());
                    self.handlers.push(CheckedHandler {
                        event_type,
                        has_predicate: predicate.is_some(),
                        author,
                        tag_equals,
                        body_items: body.len(),
                        body: body.clone(),
                        span,
                    });
                } else {
                    self.diagnostics.push(Diagnostic {
                        code: "E1302",
                        message: "handler source must name an event type".to_owned(),
                        span: source.span,
                    });
                }
                let mut handler = locals.clone();
                handler.insert(
                    "event".to_owned(),
                    TypeRef {
                        name: "Signed<Event>".to_owned(),
                        arguments: Vec::new(),
                        span,
                    },
                );
                self.check_items(body, &mut handler);
            }
            StatementKind::Once { key, body } => {
                self.effects.insert(Effect::Storage);
                self.check_expr(key, locals);
                self.require_named(span, "storage");
                self.check_items(body, &mut locals.clone());
            }
            StatementKind::Every { duration, body }
            | StatementKind::At {
                schedule: duration,
                body,
            } => {
                self.effects.insert(Effect::Clock);
                self.require_named(span, "clock");
                self.check_expr(duration, locals);
                let every = matches!(statement, StatementKind::Every { .. });
                if let Some(value) = schedule_value(duration, every) {
                    self.schedules.push(CheckedSchedule {
                        kind: if every {
                            CheckedScheduleKind::Every
                        } else {
                            CheckedScheduleKind::At
                        },
                        value,
                        span,
                    });
                } else {
                    self.diagnostics.push(Diagnostic {
                        code: "E1301",
                        message: if every {
                            "every requires a literal duration (s, m, h, or d)".to_owned()
                        } else {
                            "at requires a non-negative integer timestamp".to_owned()
                        },
                        span: duration.span,
                    });
                }
                self.check_items(body, &mut locals.clone());
            }
            StatementKind::Send { value, signer } => {
                self.check_expr(value, locals);
                if let Some(signer) = signer {
                    self.check_expr(signer, locals);
                }
            }
            StatementKind::Return(None) => {}
        }
    }

    #[allow(clippy::too_many_lines)]
    fn check_expr(&mut self, expression: &Expr, locals: &BTreeMap<String, TypeRef>) {
        match &expression.value {
            ExprKind::Select(select) => {
                self.effects.insert(Effect::Relay);
                let relay = select.relays.as_deref().and_then(identifier);
                if !self
                    .permissions
                    .reads
                    .contains(&(select.event.name.clone(), relay.map(str::to_owned)))
                {
                    self.missing_permission(expression.span, "read");
                }
                if let Some(predicate) = &select.predicate {
                    if !lowerable(predicate)
                        && select.limit.is_none()
                        && select.since.is_none()
                        && select.until.is_none()
                    {
                        self.diagnostics.push(Diagnostic {
                            code: "E2401",
                            message:
                                "query requires local filtering but has no finite remote bound"
                                    .to_owned(),
                            span: predicate.span,
                        });
                    }
                    self.check_expr(predicate, locals);
                }
            }
            ExprKind::Publish {
                value,
                relays,
                signer,
            } => self.check_publish(
                expression.span,
                value,
                relays.as_deref(),
                signer.as_deref(),
                locals,
            ),
            ExprKind::Sign { value, signer } => {
                self.effects.insert(Effect::Sign);
                self.check_expr(value, locals);
                self.check_expr(signer, locals);
            }
            ExprKind::Fetch { url, .. } => {
                self.effects.insert(Effect::Http);
                self.require_named(expression.span, "http");
                self.check_expr(url, locals);
            }
            ExprKind::Match { value, arms } => {
                self.check_expr(value, locals);
                self.check_match(expression.span, value, arms);
                for arm in arms {
                    self.check_expr(&arm.value, locals);
                }
            }
            ExprKind::Call { callee, arguments } => {
                if let Some(path) = expression_path(callee)
                    && let Some((module, operation)) = path.split_once('.')
                {
                    let checked_arguments = arguments.iter().filter_map(checked_argument).collect();
                    self.operation_calls.push(CheckedOperationCall {
                        module: module.to_owned(),
                        operation: operation.to_owned(),
                        arguments: checked_arguments,
                        span: expression.span,
                    });
                }
                if matches!(&callee.value, ExprKind::Identifier(name) if name == "print") {
                    self.effects.insert(Effect::Log);
                    self.require_named(expression.span, "log");
                }
                self.check_expr(callee, locals);
                for argument in arguments {
                    self.check_expr(argument, locals);
                }
            }
            ExprKind::Member { value, .. }
            | ExprKind::Propagate(value)
            | ExprKind::Unary { value, .. } => self.check_expr(value, locals),
            ExprKind::Binary { left, right, .. }
            | ExprKind::Assign {
                target: left,
                value: right,
            }
            | ExprKind::Index {
                value: left,
                index: right,
            } => {
                self.check_expr(left, locals);
                self.check_expr(right, locals);
            }
            ExprKind::List(values) => {
                for value in values {
                    self.check_expr(value, locals);
                }
            }
            ExprKind::Record(fields) | ExprKind::Construct { fields, .. } => {
                for (_, value) in fields {
                    self.check_expr(value, locals);
                }
            }
            ExprKind::Latest { relays, .. } => {
                self.effects.insert(Effect::Relay);
                if let Some(relays) = relays {
                    self.check_expr(relays, locals);
                }
            }
            _ => {}
        }
    }

    fn check_publish(
        &mut self,
        span: Span,
        value: &Expr,
        relays: Option<&Expr>,
        signer: Option<&Expr>,
        _locals: &BTreeMap<String, TypeRef>,
    ) {
        self.effects.insert(Effect::Relay);
        let event = match &value.value {
            ExprKind::Construct { name, .. } => name.value.clone(),
            ExprKind::Identifier(name) => {
                if self.event_bindings.contains(name) {
                    "Note".to_owned()
                } else {
                    "Event".to_owned()
                }
            }
            _ => "Event".to_owned(),
        };
        let relayset = relays
            .and_then(identifier)
            .map(str::to_owned)
            .or_else(|| self.defaults_relays.clone());
        let signer_name = signer
            .and_then(identifier)
            .map(str::to_owned)
            .or_else(|| self.defaults_signer.clone());
        if relayset.is_none() {
            return;
        }
        if signer_name.is_none() {
            if matches!(value.value, ExprKind::Identifier(_)) {
                self.diagnostics.push(Diagnostic {
                    code: "E2201",
                    message: "cannot publish an unsigned event without an allowed signer"
                        .to_owned(),
                    span,
                });
            }
            return;
        }
        self.effects.insert(Effect::Sign);
        let relayset = relayset.unwrap();
        let signer_name = signer_name.unwrap();
        if !self
            .permissions
            .publishes
            .contains(&(event.clone(), Some(relayset.clone())))
            && !self.permissions.publishes.contains(&(event.clone(), None))
        {
            self.missing_permission(span, "publish");
        }
        if !self
            .permissions
            .signs
            .contains(&(event.clone(), Some(signer_name.clone())))
            && !self.permissions.signs.contains(&(event.clone(), None))
        {
            self.missing_permission(span, "sign");
        }
        let content = match &value.value {
            ExprKind::Construct { fields, .. } => fields
                .iter()
                .find(|(name, _)| name.value == "content")
                .and_then(|(_, value)| match &value.value {
                    ExprKind::Text(text) => Some(text.clone()),
                    _ => None,
                }),
            _ => None,
        };
        self.publications.push(CheckedPublication {
            event,
            content,
            signer: signer_name,
            relayset,
            span,
        });
    }

    fn check_match(&mut self, span: Span, value: &Expr, arms: &[nscript_syntax::ast::MatchArm]) {
        let mut wildcard = false;
        let mut variants = BTreeSet::new();
        for arm in arms {
            if wildcard {
                self.diagnostics.push(Diagnostic {
                    code: "E1302",
                    message: "pattern is unreachable after a catch-all arm".to_owned(),
                    span: arm.pattern.span,
                });
                break;
            }
            // A guarded arm may not match, so it neither ends the match (a
            // catch-all) nor covers its variant. A variant whose payload tests a
            // literal (`Ok(1)`) covers only that value, so it does not count
            // either.
            let unconditional = arm.guard.is_none();
            match &arm.pattern.value {
                PatternKind::Wildcard | PatternKind::Binding(_) if unconditional => {
                    wildcard = true;
                }
                PatternKind::Variant { name, values }
                    if unconditional
                        && !values.iter().any(|value| tests_a_literal(&value.value)) =>
                {
                    variants.insert(name.clone());
                }
                _ => {}
            }
        }
        if wildcard {
            return;
        }
        let type_name = identifier(value).and_then(|name| {
            self.program.ast.items.iter().find_map(|item| match item {
                Item::Function(function) => function
                    .parameters
                    .iter()
                    .find(|parameter| parameter.name.value == name)
                    .map(|parameter| parameter.type_ref.name.as_str()),
                _ => None,
            })
        });
        let exhaustive = match type_name {
            Some("Result") => variants.contains("Ok") && variants.contains("Err"),
            Some("Option") => variants.contains("Some") && variants.contains("None"),
            _ => true,
        };
        if !exhaustive {
            self.diagnostics.push(Diagnostic {
                code: "E1301",
                message: "match does not cover every variant".to_owned(),
                span,
            });
        }
    }

    fn require_named(&mut self, span: Span, permission: &str) {
        if !self.permissions.operations.contains(permission) {
            self.missing_permission(span, permission);
        }
    }
    fn missing_permission(&mut self, span: Span, permission: &str) {
        self.diagnostics.push(Diagnostic {
            code: "E3001",
            message: format!("operation requires `{permission}` permission"),
            span,
        });
    }
}

fn checked_argument(expression: &Expr) -> Option<CheckedArgument> {
    match &expression.value {
        ExprKind::Text(value) => Some(CheckedArgument::Text(value.clone())),
        ExprKind::Integer(value) => Some(CheckedArgument::Integer(*value)),
        ExprKind::Identifier(value) => Some(CheckedArgument::PubKey(value.clone())),
        ExprKind::Construct { name, fields } => Some(CheckedArgument::Record {
            name: name.value.clone(),
            fields: fields
                .iter()
                .filter_map(|(field, value)| Some((field.value.clone(), checked_argument(value)?)))
                .collect(),
        }),
        _ => None,
    }
}

fn identifier(expression: &Expr) -> Option<&str> {
    match &expression.value {
        ExprKind::Identifier(name) => Some(name),
        _ => None,
    }
}

fn lowerable(expression: &Expr) -> bool {
    match &expression.value {
        ExprKind::Binary {
            operator,
            left,
            right,
        } if matches!(operator.as_str(), "and" | "or") => lowerable(left) && lowerable(right),
        ExprKind::Binary { operator, left, .. }
            if matches!(operator.as_str(), "==" | "contains") =>
        {
            path(left).is_some_and(|value| {
                value == "author" || value == "event.id" || value.starts_with("tags.")
            })
        }
        _ => false,
    }
}

fn path(expression: &Expr) -> Option<String> {
    match &expression.value {
        ExprKind::Identifier(name) => Some(name.clone()),
        ExprKind::Member { value, name } => Some(format!("{}.{}", path(value)?, name.value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nscript_modules::{ModuleDependency, ModuleOrigin, ModuleRegistry, parse_module};
    use nscript_syntax::parse_program;
    use semver::VersionReq;

    use super::{analyze, analyze_with_modules};

    fn codes(source: &str) -> Vec<&'static str> {
        let (program, mut diagnostics) = parse_program(source);
        diagnostics.extend(analyze(&program));
        diagnostics
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    #[test]
    fn accepts_declared_defaults() {
        let source = "signer account = nip46()\nrelayset public = configured\n\
            defaults { signer: account; relays: public }\n\
            permissions { publish Note to public; sign Note with account; relay public }\n\
            publish Note { content: \"hi\" }\n";
        assert!(codes(source).is_empty());
    }

    #[test]
    fn reports_missing_defaults() {
        assert_eq!(
            codes("publish Note { content: \"hi\" }\n"),
            ["E2203", "E2204"]
        );
    }

    #[test]
    fn hardened_profile_rejects_secret_key() {
        let diagnostics = codes("runtime hardened-agent\nlet key: SecretKey = keys.generate()\n");
        assert!(diagnostics.contains(&"E5001"));
    }

    #[test]
    fn hardened_profile_rejects_transitive_forbidden_effect() {
        let (descriptor, module_diagnostics) = parse_module(
            "module dangerous @ 0.1.0\n\
             language \">=0.1.0 <0.2.0\"\n\
             operation escape() -> Text effect Filesystem permission filesystem\n",
        );
        assert!(module_diagnostics.is_empty(), "{module_diagnostics:?}");
        let mut registry = ModuleRegistry::default();
        registry
            .register(
                descriptor.expect("test module parses"),
                ModuleOrigin::BuiltIn("test".to_owned()),
            )
            .expect("test module registers");
        let source = "runtime hardened-agent\nuse dangerous\npermissions { filesystem }\nlet result = dangerous.escape()\n";
        let (program, mut diagnostics) = parse_program(source);
        let graph = registry
            .resolve(&[ModuleDependency {
                name: "dangerous".to_owned(),
                requirement: VersionReq::STAR,
            }])
            .expect("test module resolves");
        diagnostics.extend(analyze_with_modules(&program, &graph));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "E5001"
                && diagnostic
                    .message
                    .contains("transitively requires forbidden effect")
        }));
    }

    #[test]
    fn accepts_default_publish_fixture() {
        let source = include_str!("../../../conformance/valid/default-publish.ns");
        assert!(codes(source).is_empty());
    }

    #[test]
    fn rejects_missing_default_fixtures() {
        let signer = include_str!("../../../conformance/invalid/missing-default-signer.ns");
        let relays = include_str!("../../../conformance/invalid/missing-default-relays.ns");
        assert_eq!(codes(signer), ["E2203"]);
        assert_eq!(codes(relays), ["E2204"]);
    }

    #[test]
    fn checks_imported_module_operation_arity_and_permission() {
        let source = "use nip44\nlet result = nip44.encrypt_text(\"hello\")\n";
        let (program, mut diagnostics) = parse_program(source);
        let registry = ModuleRegistry::with_builtins();
        let graph = registry
            .resolve(&[ModuleDependency {
                name: "nip44".to_owned(),
                requirement: VersionReq::STAR,
            }])
            .expect("builtin nip44 resolves");
        diagnostics.extend(analyze_with_modules(&program, &graph));
        let codes = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>();
        assert!(codes.contains(&"E1102"));
        assert!(codes.contains(&"E3001"));
    }

    #[test]
    fn accepts_imported_module_operation_with_permission() {
        let source = "use nip44\npermissions { encrypt Text }\nlet result = nip44.encrypt_text(\"hello\", alice)\n";
        let (program, mut diagnostics) = parse_program(source);
        let registry = ModuleRegistry::with_builtins();
        let graph = registry
            .resolve(&[ModuleDependency {
                name: "nip44".to_owned(),
                requirement: VersionReq::STAR,
            }])
            .expect("builtin nip44 resolves");
        diagnostics.extend(analyze_with_modules(&program, &graph));
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "E1102" || diagnostic.code == "E3001"),
            "unexpected diagnostics: {diagnostics:?}"
        );
    }
}
