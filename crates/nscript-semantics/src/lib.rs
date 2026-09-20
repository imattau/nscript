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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckedProgram {
    pub effects: BTreeSet<Effect>,
    pub publications: Vec<CheckedPublication>,
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
    diagnostics
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

#[must_use]
pub fn check(program: &Program) -> (Option<CheckedProgram>, Vec<Diagnostic>) {
    let mut checker = Checker::new(program);
    checker.check_items(&program.ast.items, &mut BTreeMap::new());
    let result = checker.diagnostics.is_empty().then_some(CheckedProgram {
        effects: checker.effects,
        publications: checker.publications,
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
            match &arm.pattern.value {
                PatternKind::Wildcard | PatternKind::Binding(_) => wildcard = true,
                PatternKind::Variant { name, .. } => {
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
    use nscript_syntax::parse_program;

    use super::analyze;

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
}
