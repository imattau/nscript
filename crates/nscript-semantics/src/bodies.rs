//! What the evaluator cannot do with code that runs.
//!
//! Handlers, functions and schedules are executed sequentially by the
//! evaluator. Two things stop it there that `check` used to accept, and this
//! pass reports both at `check` time instead:
//!
//! - **Undeclared names.** The evaluator resolves a name from the enclosing
//!   scopes, from `event` (in a handler), from `me`, or from a declared `key`;
//!   anything else stops the handler with "unknown name". The pass mirrors the
//!   evaluator rather than the other way round, so it is exactly as strict as
//!   running the code would be: a top-level `let` is not visible inside a
//!   handler, a `let` ends with its block, and `event` is not visible inside a
//!   function.
//! - **Relay queries.** `select` and `latest` can be a stream source or a
//!   top-level query, but the relay host has no way to answer one from running
//!   code, so using either inside a handler, function or schedule is an
//!   unavailable capability.
//!
//! Top-level statements outside a schedule are evaluated by a separate,
//! lenient pass and are not checked here.

use std::collections::BTreeSet;

use nscript_syntax::{
    Diagnostic, Program,
    ast::{Expr, ExprKind, Item, PatternKind, StatementKind},
};

struct Names<'a> {
    keys: BTreeSet<&'a str>,
    /// Names declared by a top-level `let`, which no handler or function sees.
    top_level_lets: BTreeSet<&'a str>,
    modules: BTreeSet<&'a str>,
    diagnostics: Vec<Diagnostic>,
    /// Innermost scope last.
    scopes: Vec<BTreeSet<String>>,
    in_handler: bool,
}

pub(crate) fn validate(program: &Program, known_modules: &BTreeSet<String>) -> Vec<Diagnostic> {
    let keys = program
        .ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Key(key) => Some(key.name.value.as_str()),
            _ => None,
        })
        .collect();
    let top_level_lets = program
        .ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Let(declaration) => Some(declaration.name.value.as_str()),
            _ => None,
        })
        .collect();
    let mut modules: BTreeSet<&str> = known_modules.iter().map(String::as_str).collect();
    modules.extend(program.imports.iter().map(|import| import.path.as_str()));
    let mut names = Names {
        keys,
        top_level_lets,
        modules,
        diagnostics: Vec::new(),
        scopes: Vec::new(),
        in_handler: false,
    };
    for item in &program.ast.items {
        names.top_level(item);
    }
    names.diagnostics
}

impl Names<'_> {
    fn top_level(&mut self, item: &Item) {
        match item {
            Item::Function(function) => {
                self.scopes = vec![
                    function
                        .parameters
                        .iter()
                        .map(|parameter| parameter.name.value.clone())
                        .collect(),
                ];
                self.in_handler = false;
                self.block(&function.body);
            }
            Item::Statement(statement) => self.top_level_statement(&statement.value),
            _ => {}
        }
    }

    fn top_level_statement(&mut self, statement: &StatementKind) {
        match statement {
            StatementKind::On { body, .. } => {
                self.scopes = vec![BTreeSet::from(["event".to_owned()])];
                self.in_handler = true;
                self.block(body);
            }
            StatementKind::Every { body, .. } | StatementKind::At { body, .. } => {
                self.scopes = vec![BTreeSet::new()];
                self.in_handler = false;
                self.block(body);
            }
            _ => {}
        }
    }

    fn declared(&self, name: &str) -> bool {
        self.scopes.iter().any(|scope| scope.contains(name))
    }

    fn bind(&mut self, name: &str) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_owned());
        }
    }

    fn block(&mut self, items: &[Item]) {
        self.scopes.push(BTreeSet::new());
        for item in items {
            match item {
                Item::Let(declaration) => {
                    self.expression(&declaration.value);
                    self.bind(&declaration.name.value);
                }
                Item::Statement(statement) => self.statement(&statement.value),
                // Anything else (a nested `fn`, a declaration) binds no value
                // here; a nested `fn` is checked as its own body.
                _ => {}
            }
        }
        self.scopes.pop();
    }

    fn statement(&mut self, statement: &StatementKind) {
        match statement {
            StatementKind::Expression(value) | StatementKind::Return(Some(value)) => {
                self.expression(value);
            }
            StatementKind::For {
                binding,
                value,
                body,
            } => {
                self.expression(value);
                self.scopes.push(BTreeSet::from([binding.value.clone()]));
                self.block(body);
                self.scopes.pop();
            }
            StatementKind::If {
                condition,
                then_body,
                else_body,
            } => {
                self.expression(condition);
                self.block(then_body);
                self.block(else_body);
            }
            StatementKind::Once { key, body } => {
                self.expression(key);
                self.block(body);
            }
            StatementKind::Every { body, .. } | StatementKind::At { body, .. } => {
                self.block(body);
            }
            StatementKind::Send { value, .. } => {
                // The signer names a capability, not a value.
                self.expression(value);
            }
            StatementKind::On { .. } | StatementKind::Return(None) => {}
        }
    }

    fn expression(&mut self, expression: &Expr) {
        match &expression.value {
            ExprKind::Identifier(name) => self.reference(name, expression),
            ExprKind::Member { value, .. } => {
                // `module.name` names a module, not a value.
                if !matches!(&value.value, ExprKind::Identifier(base) if self.modules.contains(base.as_str()) && !self.declared(base))
                {
                    self.expression(value);
                }
            }
            ExprKind::Call { callee, arguments } => {
                // A bare callee is resolved by call resolution.
                if !matches!(callee.value, ExprKind::Identifier(_)) {
                    self.expression(callee);
                }
                for argument in arguments {
                    self.expression(argument);
                }
            }
            ExprKind::Index { value, index } => {
                self.expression(value);
                self.expression(index);
            }
            ExprKind::Unary { value, .. } | ExprKind::Propagate(value) => self.expression(value),
            ExprKind::Binary { left, right, .. } => {
                self.expression(left);
                self.expression(right);
            }
            ExprKind::Assign { target, value } => {
                self.expression(target);
                self.expression(value);
            }
            ExprKind::List(values) => {
                for value in values {
                    self.expression(value);
                }
            }
            ExprKind::Record(fields) | ExprKind::Construct { fields, .. } => {
                for (_, value) in fields {
                    self.expression(value);
                }
            }
            // A `to`/`with` operand names a capability, not a value.
            ExprKind::Publish { value, .. } | ExprKind::Sign { value, .. } => {
                self.expression(value);
            }
            ExprKind::Fetch { url, .. } => self.expression(url),
            ExprKind::Match { value, arms } => {
                self.expression(value);
                for arm in arms {
                    let mut bindings = BTreeSet::new();
                    collect_bindings(&arm.pattern.value, &mut bindings);
                    self.scopes.push(bindings);
                    if let Some(guard) = &arm.guard {
                        self.expression(guard);
                    }
                    self.expression(&arm.value);
                    self.scopes.pop();
                }
            }
            ExprKind::Select(_) | ExprKind::Latest { .. } => {
                let (word, source) = match &expression.value {
                    ExprKind::Select(_) => ("select", "`stream x = select ...`"),
                    _ => ("latest", "a top-level query"),
                };
                self.diagnostics.push(Diagnostic {
                    code: "E3002",
                    message: format!(
                        "`{word}` cannot run inside a handler, function or schedule: the relay host cannot answer a query from running code; use it as {source} instead"
                    ),
                    span: expression.span,
                });
            }
            ExprKind::Integer(_)
            | ExprKind::Decimal(_)
            | ExprKind::Text(_)
            | ExprKind::Bool(_)
            | ExprKind::None
            | ExprKind::Duration { .. }
            | ExprKind::Percentage(_) => {}
        }
    }

    fn reference(&mut self, name: &str, expression: &Expr) {
        let visible = self.declared(name)
            || name == "me"
            || self.keys.contains(name)
            || (name == "event" && self.in_handler);
        if !visible {
            let message = if self.top_level_lets.contains(name) {
                format!(
                    "unknown name `{name}`: it is a top-level `let`, which handlers, functions and schedules cannot see; bind it inside the body or pass it as an argument"
                )
            } else if name == "event" {
                "unknown name `event`: it is only bound inside a handler, so a function must take what it needs as a parameter".to_owned()
            } else {
                format!("unknown name `{name}`")
            };
            self.diagnostics.push(Diagnostic {
                code: "E1101",
                message,
                span: expression.span,
            });
        }
    }
}

fn collect_bindings(pattern: &PatternKind, out: &mut BTreeSet<String>) {
    match pattern {
        PatternKind::Binding(name) => {
            out.insert(name.clone());
        }
        PatternKind::Variant { values, .. } => {
            for value in values {
                collect_bindings(&value.value, out);
            }
        }
        PatternKind::Record { fields, .. } => {
            for (field, sub) in fields {
                match sub {
                    Some(sub) => collect_bindings(&sub.value, out),
                    None => {
                        out.insert(field.clone());
                    }
                }
            }
        }
        PatternKind::Wildcard | PatternKind::Literal(_) => {}
    }
}
