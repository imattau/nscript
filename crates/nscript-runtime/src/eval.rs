//! A tree-walking evaluator for handler bodies.
//!
//! Handlers are the point of the language: `on <stream> { ... }` reacts to an
//! event by computing over it and calling module operations. The checker has
//! already validated permissions and effects; this evaluator runs the body and
//! keeps the same discipline at run time. Every module operation goes through
//! the host (and so through [`crate::OperationPolicy`]), execution is bounded
//! by a step and depth budget, and an unsupported construct is a stable error,
//! never silently skipped.
//!
//! Operation failures abort the handler, as `?` would: the language's `Result`
//! values are not yet modelled, so a script cannot yet branch on one.

use std::collections::{BTreeMap, BTreeSet};

use nscript_syntax::Program;
use nscript_syntax::ast::{
    Expr, ExprKind, FunctionDeclaration, Item, MatchArm, PatternKind, StatementKind,
};

use crate::{
    AuditEntry, AuditHost, ClockHost, IdempotencyHost, LogHost, LogRecord, OperationHost,
    OperationPolicy, OperationValue, RelayHost, Runtime, RuntimeError, SignerHost, StreamMessage,
    SubscriptionHost, SubscriptionRequest, TransactionalStorageHost,
};

/// What the evaluator needs from its surroundings.
pub trait EvalHost {
    /// `print(...)`.
    ///
    /// # Errors
    ///
    /// Returns the logging failure.
    fn print(&mut self, message: &str) -> Result<(), RuntimeError>;

    /// The program's principal, the value of `me`. `None` if not configured.
    fn principal(&self) -> Option<String>;

    /// A module operation call, already gated by the host's policy.
    ///
    /// # Errors
    ///
    /// Returns the capability, argument or operation failure.
    fn call_operation(
        &mut self,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError>;

    /// The declared return type of an operation, if known. For one declared
    /// `Result<T,E>` the evaluator returns `Ok`/`Err` values, and turns a
    /// recoverable failure into an `Err` a script can branch on. Without it an
    /// operation returns its plain value and any failure aborts the handler.
    fn declared_return(&self, _module: &str, _operation: &str) -> Option<String> {
        None
    }
}

/// A run-time value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Unit,
    Bool(bool),
    Int(i64),
    Text(String),
    /// A public key: 64 hex characters, or any text a module treats as one.
    PubKey(String),
    List(Vec<Value>),
    Record {
        name: String,
        fields: Vec<(String, Value)>,
    },
    /// The success arm of a `Result`.
    ResultOk(Box<Value>),
    /// The error arm of a `Result`.
    ResultErr(Box<Value>),
    /// An operation result the evaluator does not model, kept whole so it can
    /// be passed back into another operation.
    Op(OperationValue),
}

impl Value {
    fn kind(&self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Text(_) => "text",
            Self::PubKey(_) => "pubkey",
            Self::List(_) => "list",
            Self::Record { .. } => "record",
            Self::ResultOk(_) | Self::ResultErr(_) => "result",
            Self::Op(_) => "operation value",
        }
    }

    /// The text `print` shows.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Unit => "()".to_owned(),
            Self::Bool(value) => value.to_string(),
            Self::Int(value) => value.to_string(),
            Self::Text(value) | Self::PubKey(value) => value.clone(),
            Self::List(items) => {
                let items: Vec<_> = items.iter().map(Self::display).collect();
                format!("[{}]", items.join(", "))
            }
            Self::Record { name, fields } => {
                let fields: Vec<_> = fields
                    .iter()
                    .map(|(field, value)| format!("{field}: {}", value.display()))
                    .collect();
                format!("{name} {{ {} }}", fields.join(", "))
            }
            Self::ResultOk(value) => format!("Ok({})", value.display()),
            Self::ResultErr(value) => format!("Err({})", value.display()),
            Self::Op(value) => format!("{value:?}"),
        }
    }

    /// The delivered event as a handler sees it.
    #[must_use]
    pub fn from_event(event: &crate::SignedEvent) -> Self {
        Self::Record {
            // Named by its type, so `match event { Note { author, content } => .. }`
            // selects on it.
            name: event.unsigned.event_type.clone(),
            fields: vec![
                ("id".to_owned(), Self::Text(event.id.clone())),
                ("author".to_owned(), Self::PubKey(event.signer.clone())),
                ("pubkey".to_owned(), Self::PubKey(event.signer.clone())),
                (
                    "content".to_owned(),
                    Self::Text(event.unsigned.content.clone()),
                ),
                ("kind".to_owned(), Self::Int(i64::from(event.unsigned.kind))),
                (
                    "created_at".to_owned(),
                    Self::Int(i64::try_from(event.unsigned.created_at).unwrap_or(i64::MAX)),
                ),
                (
                    "tags".to_owned(),
                    Self::List(
                        event
                            .unsigned
                            .tags
                            .iter()
                            .map(|(name, value)| Self::Text(format!("{name}={value}")))
                            .collect(),
                    ),
                ),
            ],
        }
    }

    fn to_operation(&self) -> Result<OperationValue, Stop> {
        match self {
            Self::Text(value) => Ok(OperationValue::Text(value.clone())),
            Self::Int(value) => Ok(OperationValue::Integer(*value)),
            Self::PubKey(value) => Ok(OperationValue::PubKey(value.clone())),
            Self::Op(value) => Ok(value.clone()),
            Self::Record { name, fields } if name == "StreamMessage" => {
                let text = |field: &str| {
                    fields.iter().find_map(|(key, value)| match value {
                        Self::Text(text) | Self::PubKey(text) if key == field => Some(text.clone()),
                        _ => None,
                    })
                };
                match (text("author"), text("content")) {
                    (Some(author), Some(content)) => {
                        Ok(OperationValue::StreamMessage(StreamMessage {
                            author,
                            content,
                        }))
                    }
                    _ => Err(fail("a StreamMessage needs text `author` and `content`")),
                }
            }
            Self::Record { name, fields } => Ok(OperationValue::Record {
                name: name.clone(),
                fields: fields
                    .iter()
                    .map(|(field, value)| Ok((field.clone(), value.to_operation()?)))
                    .collect::<Result<_, Stop>>()?,
            }),
            other => Err(fail(format!(
                "cannot pass a {} to an operation",
                other.kind()
            ))),
        }
    }

    fn from_operation(value: OperationValue) -> Self {
        match value {
            OperationValue::Text(value) => Self::Text(value),
            OperationValue::Integer(value) => Self::Int(value),
            OperationValue::PubKey(value) => Self::PubKey(value),
            OperationValue::PublishReport(report) => Self::Record {
                name: "PublishReport".to_owned(),
                fields: vec![("accepted".to_owned(), Self::Bool(report.accepted()))],
            },
            other => Self::Op(other),
        }
    }
}

/// Bounds on one evaluation. A handler that loops or recurses without end is
/// stopped with [`RuntimeError::ResourceLimit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvalLimits {
    pub max_steps: u64,
    pub max_depth: usize,
}

impl Default for EvalLimits {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            max_depth: 32,
        }
    }
}

/// Why an evaluation step ended early. A real failure aborts the handler; a `?`
/// on an error result instead returns that error from the nearest enclosing
/// function or handler (the spec: "postfix `?` returns the error"), so it is
/// carried separately and caught at the function or handler boundary.
enum Stop {
    Error(RuntimeError),
    Propagate(Value),
}

impl From<RuntimeError> for Stop {
    fn from(error: RuntimeError) -> Self {
        Self::Error(error)
    }
}

fn fail(message: impl Into<String>) -> Stop {
    Stop::Error(RuntimeError::EvaluationError {
        message: message.into(),
    })
}

enum Flow {
    Next,
    Return(Value),
}

pub struct Interpreter<'a, H: EvalHost> {
    host: &'a mut H,
    functions: BTreeMap<&'a str, &'a FunctionDeclaration>,
    modules: BTreeSet<&'a str>,
    scopes: Vec<BTreeMap<String, Value>>,
    limits: EvalLimits,
    steps: u64,
    depth: usize,
}

/// Runs a handler body with `event` bound, returning the value of a `return`
/// (or `Unit`).
///
/// `program` supplies the functions the body may call and the modules it may
/// call into.
///
/// # Errors
///
/// Returns the first evaluation, capability or operation failure, or a resource
/// limit.
pub fn run_handler<'a, H: EvalHost>(
    program: &'a Program,
    body: &'a [Item],
    event: Value,
    host: &'a mut H,
    limits: EvalLimits,
) -> Result<Value, RuntimeError> {
    let functions = program
        .ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Function(function) => Some((function.name.value.as_str(), function)),
            _ => None,
        })
        .collect();
    let modules = program
        .imports
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    let mut interpreter = Interpreter {
        host,
        functions,
        modules,
        scopes: vec![BTreeMap::from([("event".to_owned(), event)])],
        limits,
        steps: 0,
        depth: 0,
    };
    match interpreter.block(body) {
        Ok(Flow::Return(value)) => Ok(value),
        Ok(Flow::Next) => Ok(Value::Unit),
        // A `?` on an error returns that error from the handler.
        Err(Stop::Propagate(error)) => Ok(Value::ResultErr(Box::new(error))),
        Err(Stop::Error(error)) => Err(error),
    }
}

impl<H: EvalHost> Interpreter<'_, H> {
    fn step(&mut self) -> Result<(), Stop> {
        self.steps += 1;
        if self.steps > self.limits.max_steps {
            return Err(RuntimeError::ResourceLimit {
                resource: "handler steps".to_owned(),
            }
            .into());
        }
        Ok(())
    }

    fn block(&mut self, items: &[Item]) -> Result<Flow, Stop> {
        self.scopes.push(BTreeMap::new());
        let result = self.items(items);
        self.scopes.pop();
        result
    }

    fn items(&mut self, items: &[Item]) -> Result<Flow, Stop> {
        for item in items {
            self.step()?;
            match item {
                Item::Let(declaration) => {
                    let value = self.expression(&declaration.value)?;
                    self.scopes
                        .last_mut()
                        .expect("a scope is always open")
                        .insert(declaration.name.value.clone(), value);
                }
                Item::Statement(statement) => {
                    if let Flow::Return(value) = self.statement(&statement.value)? {
                        return Ok(Flow::Return(value));
                    }
                }
                other => {
                    return Err(unsupported(
                        &format!("{other:?}").chars().take(24).collect::<String>(),
                    ));
                }
            }
        }
        Ok(Flow::Next)
    }

    fn statement(&mut self, statement: &StatementKind) -> Result<Flow, Stop> {
        match statement {
            StatementKind::Expression(expression) => {
                self.expression(expression)?;
                Ok(Flow::Next)
            }
            StatementKind::Return(value) => {
                let value = match value {
                    Some(expression) => self.expression(expression)?,
                    None => Value::Unit,
                };
                Ok(Flow::Return(value))
            }
            StatementKind::If {
                condition,
                then_body,
                else_body,
            } => {
                if self.condition(condition)? {
                    self.block(then_body)
                } else {
                    self.block(else_body)
                }
            }
            StatementKind::For {
                binding,
                value,
                body,
            } => {
                let Value::List(items) = self.expression(value)? else {
                    return Err(fail("`for` iterates a list"));
                };
                for item in items {
                    self.step()?;
                    self.scopes
                        .push(BTreeMap::from([(binding.value.clone(), item)]));
                    let flow = self.items(body);
                    self.scopes.pop();
                    if let Flow::Return(value) = flow? {
                        return Ok(Flow::Return(value));
                    }
                }
                Ok(Flow::Next)
            }
            StatementKind::On { .. }
            | StatementKind::Once { .. }
            | StatementKind::Every { .. }
            | StatementKind::At { .. }
            | StatementKind::Send { .. } => Err(unsupported("nested handler or send statement")),
        }
    }

    fn condition(&mut self, expression: &Expr) -> Result<bool, Stop> {
        match self.expression(expression)? {
            Value::Bool(value) => Ok(value),
            other => Err(fail(format!(
                "a condition must be a bool, found a {}",
                other.kind()
            ))),
        }
    }

    fn lookup(&self, name: &str) -> Option<&Value> {
        self.scopes.iter().rev().find_map(|scope| scope.get(name))
    }

    fn expression(&mut self, expression: &Expr) -> Result<Value, Stop> {
        self.step()?;
        match &expression.value {
            ExprKind::Integer(value) => Ok(Value::Int(*value)),
            ExprKind::Text(value) => Ok(Value::Text(value.clone())),
            ExprKind::Bool(value) => Ok(Value::Bool(*value)),
            ExprKind::None => Ok(Value::Unit),
            ExprKind::Identifier(name) => self.identifier(name),
            ExprKind::List(items) => Ok(Value::List(
                items
                    .iter()
                    .map(|item| self.expression(item))
                    .collect::<Result<_, _>>()?,
            )),
            ExprKind::Construct { name, fields } => Ok(Value::Record {
                name: name.value.clone(),
                fields: fields
                    .iter()
                    .map(|(field, value)| Ok((field.value.clone(), self.expression(value)?)))
                    .collect::<Result<_, Stop>>()?,
            }),
            ExprKind::Member { value, name } => match self.expression(value)? {
                Value::Record { fields, .. } => fields
                    .into_iter()
                    .find_map(|(field, value)| (field == name.value).then_some(value))
                    .ok_or_else(|| fail(format!("no field `{}`", name.value))),
                other => Err(fail(format!("a {} has no fields", other.kind()))),
            },
            ExprKind::Index { value, index } => {
                let (Value::List(items), Value::Int(at)) =
                    (self.expression(value)?, self.expression(index)?)
                else {
                    return Err(fail("indexing needs a list and an int"));
                };
                usize::try_from(at)
                    .ok()
                    .and_then(|at| items.into_iter().nth(at))
                    .ok_or_else(|| fail("index out of range"))
            }
            ExprKind::Unary { operator, value } => self.unary(operator, value),
            ExprKind::Binary {
                operator,
                left,
                right,
            } => self.binary(operator, left, right),
            ExprKind::Assign { target, value } => {
                let ExprKind::Identifier(name) = &target.value else {
                    return Err(fail("only a name can be assigned to"));
                };
                let value = self.expression(value)?;
                for scope in self.scopes.iter_mut().rev() {
                    if let Some(slot) = scope.get_mut(name) {
                        *slot = value;
                        return Ok(Value::Unit);
                    }
                }
                Err(fail(format!("assignment to undeclared name `{name}`")))
            }
            // `?` unwraps a success and returns an error from the nearest
            // enclosing function or handler. A value that is not a result passes
            // through: it came from an operation whose result type is not
            // modelled.
            ExprKind::Propagate(value) => match self.expression(value)? {
                Value::ResultOk(inner) => Ok(*inner),
                Value::ResultErr(error) => Err(Stop::Propagate(*error)),
                other => Ok(other),
            },
            ExprKind::Match { value, arms } => self.match_expression(value, arms),
            ExprKind::Call { callee, arguments } => self.call(callee, arguments),
            other => Err(unsupported(
                &format!("{other:?}").chars().take(24).collect::<String>(),
            )),
        }
    }

    fn identifier(&self, name: &str) -> Result<Value, Stop> {
        if let Some(value) = self.lookup(name) {
            return Ok(value.clone());
        }
        if name == "me" {
            return self
                .host
                .principal()
                .map(Value::PubKey)
                .ok_or_else(|| fail("`me` is not configured"));
        }
        Err(fail(format!("unknown name `{name}`")))
    }

    fn unary(&mut self, operator: &str, value: &Expr) -> Result<Value, Stop> {
        match (operator, self.expression(value)?) {
            ("!" | "not", Value::Bool(value)) => Ok(Value::Bool(!value)),
            ("-", Value::Int(value)) => value
                .checked_neg()
                .map(Value::Int)
                .ok_or_else(|| fail("integer overflow")),
            (operator, other) => Err(fail(format!(
                "`{operator}` does not apply to a {}",
                other.kind()
            ))),
        }
    }

    fn binary(&mut self, operator: &str, left: &Expr, right: &Expr) -> Result<Value, Stop> {
        // `and` / `or` short-circuit, so the right side may be a guarded call.
        if matches!(operator, "and" | "&&" | "or" | "||") {
            let short = matches!(operator, "or" | "||");
            if self.condition(left)? == short {
                return Ok(Value::Bool(short));
            }
            return Ok(Value::Bool(self.condition(right)?));
        }
        let (left, right) = (self.expression(left)?, self.expression(right)?);
        match operator {
            "==" => Ok(Value::Bool(same(&left, &right))),
            "!=" => Ok(Value::Bool(!same(&left, &right))),
            "contains" => contains(&left, &right).map(Value::Bool),
            "in" => contains(&right, &left).map(Value::Bool),
            "<" | ">" | "<=" | ">=" => compare(operator, &left, &right).map(Value::Bool),
            "+" | "-" | "*" | "/" | "%" => arithmetic(operator, &left, &right),
            other => Err(unsupported(&format!("operator {other}"))),
        }
    }

    fn call(&mut self, callee: &Expr, arguments: &[Expr]) -> Result<Value, Stop> {
        let arguments = arguments
            .iter()
            .map(|argument| self.expression(argument))
            .collect::<Result<Vec<_>, _>>()?;
        match &callee.value {
            ExprKind::Identifier(name) if name == "print" => {
                let [value] = arguments.as_slice() else {
                    return Err(fail("`print` takes one argument"));
                };
                self.host.print(&value.display())?;
                Ok(Value::Unit)
            }
            ExprKind::Identifier(name) if name == "len" => match arguments.as_slice() {
                [Value::List(items)] => {
                    Ok(Value::Int(i64::try_from(items.len()).unwrap_or(i64::MAX)))
                }
                [Value::Text(text)] => Ok(Value::Int(
                    i64::try_from(text.chars().count()).unwrap_or(i64::MAX),
                )),
                _ => Err(fail("`len` takes a list or text")),
            },
            ExprKind::Identifier(name) if name == "Ok" || name == "Err" => {
                let [value] = arguments.as_slice() else {
                    return Err(fail(format!("`{name}` takes one argument")));
                };
                let value = Box::new(value.clone());
                Ok(if name == "Ok" {
                    Value::ResultOk(value)
                } else {
                    Value::ResultErr(value)
                })
            }
            ExprKind::Identifier(name) => self.call_function(name, arguments),
            ExprKind::Member { value, name } if matches!(&value.value, ExprKind::Identifier(module) if self.modules.contains(module.as_str())) =>
            {
                let ExprKind::Identifier(module) = &value.value else {
                    unreachable!("guarded above")
                };
                let operands = arguments
                    .iter()
                    .map(Value::to_operation)
                    .collect::<Result<Vec<_>, _>>()?;
                let declared = self.host.declared_return(module, &name.value);
                let outcome = self.host.call_operation(module, &name.value, &operands);
                match declared.as_deref().and_then(result_error_type) {
                    // Declared `Result<T,E>`: hand the script `Ok`/`Err`. A failure
                    // that is not the operation's to report (a capability denial, a
                    // bad argument) still aborts the handler.
                    Some(error_type) => Ok(match outcome {
                        Ok(value) => Value::ResultOk(Box::new(Value::from_operation(value))),
                        Err(error) => match recoverable(&error, &error_type) {
                            Some(failure) => Value::ResultErr(Box::new(failure)),
                            None => return Err(Stop::Error(error)),
                        },
                    }),
                    None => Ok(Value::from_operation(outcome?)),
                }
            }
            _ => Err(fail("this call is not supported")),
        }
    }

    fn call_function(&mut self, name: &str, arguments: Vec<Value>) -> Result<Value, Stop> {
        let function = *self
            .functions
            .get(name)
            .ok_or_else(|| fail(format!("unknown function `{name}`")))?;
        if function.parameters.len() != arguments.len() {
            return Err(fail(format!(
                "`{name}` takes {} arguments",
                function.parameters.len()
            )));
        }
        if self.depth >= self.limits.max_depth {
            return Err(RuntimeError::ResourceLimit {
                resource: "handler call depth".to_owned(),
            }
            .into());
        }
        self.depth += 1;
        // A function sees only its own parameters, never the caller's names.
        let caller = std::mem::replace(
            &mut self.scopes,
            vec![
                function
                    .parameters
                    .iter()
                    .zip(arguments)
                    .map(|(parameter, value)| (parameter.name.value.clone(), value))
                    .collect(),
            ],
        );
        let result = self.block(&function.body);
        self.scopes = caller;
        self.depth -= 1;
        match result {
            Ok(Flow::Return(value)) => Ok(value),
            Ok(Flow::Next) => Ok(Value::Unit),
            // `?` inside a function returns the error from that function.
            Err(Stop::Propagate(error)) => Ok(Value::ResultErr(Box::new(error))),
            Err(other) => Err(other),
        }
    }

    fn match_expression(&mut self, value: &Expr, arms: &[MatchArm]) -> Result<Value, Stop> {
        let subject = self.expression(value)?;
        for arm in arms {
            self.step()?;
            let mut bindings = BTreeMap::new();
            if !pattern_matches(&arm.pattern.value, &subject, &mut bindings) {
                continue;
            }
            self.scopes.push(bindings);
            let outcome = match &arm.guard {
                Some(guard) => self.condition(guard).and_then(|held| {
                    if held {
                        self.expression(&arm.value).map(Some)
                    } else {
                        Ok(None)
                    }
                }),
                None => self.expression(&arm.value).map(Some),
            };
            self.scopes.pop();
            if let Some(chosen) = outcome? {
                return Ok(chosen);
            }
        }
        // The checker cannot always prove a match exhaustive (a call's result has
        // no declared type it can see), so a value no arm covers is an error
        // here, never a silent fall-through.
        Err(fail("no `match` arm matched the value"))
    }
}

/// Whether `value` fits `pattern`, collecting its bindings. Bindings from a
/// failed attempt are discarded by the caller.
fn pattern_matches(
    pattern: &PatternKind,
    value: &Value,
    bindings: &mut BTreeMap<String, Value>,
) -> bool {
    match pattern {
        PatternKind::Wildcard => true,
        PatternKind::Binding(name) => {
            bindings.insert(name.clone(), value.clone());
            true
        }
        PatternKind::Literal(literal) => match (literal, value) {
            (ExprKind::Integer(a), Value::Int(b)) => a == b,
            (ExprKind::Text(a), Value::Text(b) | Value::PubKey(b)) => a == b,
            (ExprKind::Bool(a), Value::Bool(b)) => a == b,
            (ExprKind::None, Value::Unit) => true,
            _ => false,
        },
        PatternKind::Variant { name, values } => match (name.as_str(), value, values.as_slice()) {
            ("Ok", Value::ResultOk(inner), [pattern])
            | ("Err", Value::ResultErr(inner), [pattern]) => {
                pattern_matches(&pattern.value, inner, bindings)
            }
            _ => false,
        },
        PatternKind::Record { name, fields } => {
            let Value::Record {
                name: actual,
                fields: actual_fields,
            } = value
            else {
                return false;
            };
            name == actual
                && fields.iter().all(|(field, sub)| {
                    let Some((_, found)) = actual_fields.iter().find(|(key, _)| key == field)
                    else {
                        return false;
                    };
                    if let Some(sub) = sub {
                        pattern_matches(&sub.value, found, bindings)
                    } else {
                        // `{ author }` binds the field to its own name.
                        bindings.insert(field.clone(), found.clone());
                        true
                    }
                })
        }
    }
}

/// The error type `E` of a declared `Result<T,E>`, splitting at the top-level
/// comma so `Result<List<X>,E>` works.
fn result_error_type(declared: &str) -> Option<String> {
    let inner = declared.strip_prefix("Result<")?.strip_suffix('>')?;
    let mut depth = 0_usize;
    for (index, character) in inner.char_indices() {
        match character {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return Some(inner[index + 1..].trim().to_owned()),
            _ => {}
        }
    }
    None
}

/// An operation's own failure as an error value a script can branch on. Only
/// failures the operation legitimately reports are recoverable: a refusal by the
/// roster, an unreachable relay, a rejected publication. A capability denial, a
/// bad argument or a resource limit is the program's mistake or the host's
/// boundary, and must abort rather than be caught.
fn recoverable(error: &RuntimeError, error_type: &str) -> Option<Value> {
    let message = match error {
        RuntimeError::AuthorityDenied { action, .. } => format!("not authorized to {action}"),
        RuntimeError::RelayUnavailable { relayset } => {
            format!("relay set `{relayset}` is unavailable")
        }
        RuntimeError::PublicationRejected => "publication rejected".to_owned(),
        RuntimeError::StoreConflict => "storage conflict".to_owned(),
        RuntimeError::SignerDenied { signer } => format!("signer `{signer}` was denied"),
        RuntimeError::PaymentLimitExceeded { amount, limit } => {
            format!("payment of {amount} exceeds the limit of {limit}")
        }
        _ => return None,
    };
    Some(Value::Record {
        name: error_type.to_owned(),
        fields: vec![("message".to_owned(), Value::Text(message))],
    })
}

/// A handler that ends by returning an error result has failed: it becomes an
/// error, so its transaction rolls back and it is reported.
fn settle(result: Result<Value, RuntimeError>) -> Result<Value, RuntimeError> {
    match result {
        Ok(Value::ResultErr(error)) => Err(RuntimeError::HandlerError {
            message: error.display(),
        }),
        other => other,
    }
}

fn unsupported(what: &str) -> Stop {
    Stop::Error(RuntimeError::OperationUnavailable {
        module: "handler".to_owned(),
        operation: what.to_owned(),
    })
}

/// Equality across the text-like kinds: a `PubKey` written as a literal is
/// text, so the two compare by their characters.
fn same(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Text(a) | Value::PubKey(a), Value::Text(b) | Value::PubKey(b)) => a == b,
        _ => left == right,
    }
}

fn contains(haystack: &Value, needle: &Value) -> Result<bool, Stop> {
    match (haystack, needle) {
        (Value::Text(text), Value::Text(needle)) => Ok(text.contains(needle.as_str())),
        (Value::List(items), needle) => Ok(items.iter().any(|item| same(item, needle))),
        _ => Err(fail(format!(
            "cannot test a {} for a {}",
            haystack.kind(),
            needle.kind()
        ))),
    }
}

fn compare(operator: &str, left: &Value, right: &Value) -> Result<bool, Stop> {
    let ordering = match (left, right) {
        (Value::Int(a), Value::Int(b)) => a.cmp(b),
        (Value::Text(a), Value::Text(b)) => a.cmp(b),
        _ => {
            return Err(fail(format!(
                "cannot order a {} and a {}",
                left.kind(),
                right.kind()
            )));
        }
    };
    Ok(match operator {
        "<" => ordering.is_lt(),
        ">" => ordering.is_gt(),
        "<=" => ordering.is_le(),
        _ => ordering.is_ge(),
    })
}

fn arithmetic(operator: &str, left: &Value, right: &Value) -> Result<Value, Stop> {
    // `+` joins text; a public key is text too.
    if let (Value::Text(a) | Value::PubKey(a), Value::Text(b) | Value::PubKey(b), "+") =
        (&left, &right, operator)
    {
        return Ok(Value::Text(format!("{a}{b}")));
    }
    let (Value::Int(a), Value::Int(b)) = (&left, &right) else {
        return Err(fail(format!(
            "`{operator}` needs two ints, found a {} and a {}",
            left.kind(),
            right.kind()
        )));
    };
    let result = match operator {
        "+" => a.checked_add(*b),
        "-" => a.checked_sub(*b),
        "*" => a.checked_mul(*b),
        "/" if *b == 0 => return Err(fail("division by zero")),
        "/" => a.checked_div(*b),
        _ if *b == 0 => return Err(fail("division by zero")),
        _ => a.checked_rem(*b),
    };
    result
        .map(Value::Int)
        .ok_or_else(|| fail("integer overflow"))
}

/// An [`EvalHost`] backed by the real [`Runtime`]: `print` is a logged, audited
/// record and every module operation goes through
/// [`Runtime::invoke_authorized_operation`], so the program's
/// [`OperationPolicy`] applies inside a handler exactly as it does outside one.
pub struct RuntimeSession<'a, R, S, C, A, O, L>
where
    R: RelayHost,
    S: SignerHost,
    C: ClockHost,
    A: AuditHost,
    O: OperationHost,
    L: LogHost,
{
    pub runtime: &'a mut Runtime<R, S, C, A>,
    pub policy: &'a OperationPolicy,
    pub operations: &'a mut O,
    pub log: &'a mut L,
    /// The value of `me`.
    pub principal: Option<String>,
}

impl<R, S, C, A, O, L> EvalHost for RuntimeSession<'_, R, S, C, A, O, L>
where
    R: RelayHost,
    S: SignerHost,
    C: ClockHost,
    A: AuditHost,
    O: OperationHost,
    L: LogHost,
{
    fn print(&mut self, message: &str) -> Result<(), RuntimeError> {
        self.runtime.log(
            self.log,
            &LogRecord {
                level: "info".to_owned(),
                message: message.to_owned(),
            },
        )
    }

    fn principal(&self) -> Option<String> {
        self.principal.clone()
    }

    fn call_operation(
        &mut self,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        self.runtime.invoke_authorized_operation(
            self.policy,
            self.operations,
            module,
            operation,
            arguments,
        )
    }

    fn declared_return(&self, module: &str, operation: &str) -> Option<String> {
        self.operations.declared_return(module, operation)
    }
}

/// Builds a [`crate::SignedEvent`] from JSON, for delivering a synthetic event
/// to handlers (`nscript run --event`). Missing fields take defaults: an
/// `event_type` of `Note`, kind 1, empty content and tags, and a placeholder
/// author, id and signature. `author` is accepted as an alias for `signer`. Tags
/// are `[name, value]` arrays; a tag with no value has an empty one.
///
/// # Errors
///
/// Returns a message for a non-object or an out-of-range `kind`.
pub fn event_from_json(value: &serde_json::Value) -> Result<crate::SignedEvent, String> {
    use serde_json::Value as Json;
    let object = value.as_object().ok_or("an event must be a JSON object")?;
    let text = |keys: &[&str], default: &str| {
        keys.iter()
            .find_map(|key| object.get(*key).and_then(Json::as_str))
            .unwrap_or(default)
            .to_owned()
    };
    let kind = u16::try_from(object.get("kind").and_then(Json::as_u64).unwrap_or(1))
        .map_err(|_| "kind must fit in 16 bits")?;
    let tags = object
        .get("tags")
        .and_then(Json::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(|tag| {
                    let tag = tag.as_array()?;
                    let name = tag.first()?.as_str()?;
                    let value = tag.get(1).and_then(Json::as_str).unwrap_or("");
                    Some((name.to_owned(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(crate::SignedEvent {
        unsigned: crate::UnsignedEvent {
            event_type: text(&["event_type"], "Note"),
            kind,
            content: text(&["content"], ""),
            tags,
            created_at: object.get("created_at").and_then(Json::as_u64).unwrap_or(0),
        },
        signer: text(&["signer", "author"], "alice"),
        id: text(&["id"], "sim-event"),
        signature: text(&["signature"], "sig"),
    })
}

/// One module operation a simulated handler made.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatedCall {
    pub module: String,
    pub operation: String,
    pub arguments: Vec<OperationValue>,
    /// `true` if no host implements the operation and it was answered from its
    /// declared return type; `false` if the fake host really ran it.
    pub simulated: bool,
}

/// The operation host for `nscript run`, which simulates and never touches the
/// network or a key. Operations the fake host implements run for real against
/// it. Every other module operation is recorded and answered from its declared
/// return type, so a script can be exercised end to end and its effects read off
/// the recorded calls.
#[derive(Default)]
pub struct SimulatedOperations {
    fake: crate::FakeOperationHost,
    /// `(module, operation)` to the declared return type, e.g.
    /// `Result<PublishReport,ModerationError>`.
    returns: BTreeMap<(String, String), String>,
    /// Operations made to fail, to exercise a script's error handling.
    failing: BTreeSet<(String, String)>,
    pub calls: Vec<SimulatedCall>,
}

impl SimulatedOperations {
    #[must_use]
    pub fn new(returns: BTreeMap<(String, String), String>) -> Self {
        Self {
            fake: crate::FakeOperationHost::default(),
            returns,
            failing: BTreeSet::new(),
            calls: Vec::new(),
        }
    }

    /// Makes `module.operation` fail with a recoverable error (a rejected
    /// publication), so a script's `Err` handling can be exercised. The attempt
    /// is still recorded.
    pub fn fail_operation(&mut self, module: &str, operation: &str) {
        self.failing
            .insert((module.to_owned(), operation.to_owned()));
    }

    /// A benign value of the operation's declared success type.
    fn simulated_result(&self, module: &str, operation: &str) -> OperationValue {
        let declared = self
            .returns
            .get(&(module.to_owned(), operation.to_owned()))
            .map_or("", String::as_str);
        let inner = declared
            .strip_prefix("Result<")
            .map_or(declared, |rest| rest.split(',').next().unwrap_or(rest))
            .trim_end_matches('>')
            .trim();
        match inner {
            "PublishReport" => OperationValue::PublishReport(crate::PublishReport {
                outcomes: vec![crate::RelayOutcome {
                    relay: "simulated://".to_owned(),
                    accepted: true,
                    detail: "simulated".to_owned(),
                }],
            }),
            "Int" => OperationValue::Integer(0),
            _ => OperationValue::Text("simulated".to_owned()),
        }
    }
}

impl OperationHost for SimulatedOperations {
    fn call(
        &mut self,
        invocation: crate::InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        if self
            .failing
            .contains(&(module.to_owned(), operation.to_owned()))
        {
            self.calls.push(SimulatedCall {
                module: module.to_owned(),
                operation: operation.to_owned(),
                arguments: arguments.to_vec(),
                simulated: true,
            });
            return Err(RuntimeError::PublicationRejected);
        }
        let (result, simulated) = match self.fake.call(invocation, module, operation, arguments) {
            Ok(value) => (value, false),
            Err(RuntimeError::OperationUnavailable { .. }) => {
                (self.simulated_result(module, operation), true)
            }
            // A wrong argument shape or a denied capability is a real failure.
            Err(error) => return Err(error),
        };
        self.calls.push(SimulatedCall {
            module: module.to_owned(),
            operation: operation.to_owned(),
            arguments: arguments.to_vec(),
            simulated,
        });
        Ok(result)
    }

    fn declared_return(&self, module: &str, operation: &str) -> Option<String> {
        self.returns
            .get(&(module.to_owned(), operation.to_owned()))
            .cloned()
    }
}

/// Gives any operation host declared return types, so a handler evaluated over it
/// gets `Ok`/`Err` values for operations declared `Result<T,E>`. Operation calls
/// pass straight through to `inner`. The table is the same `(module, operation)`
/// to declared-type map the simulator uses, typically built from the imported
/// modules' descriptors.
pub struct WithReturns<'a, O: OperationHost> {
    pub inner: &'a mut O,
    pub returns: BTreeMap<(String, String), String>,
}

impl<O: OperationHost> OperationHost for WithReturns<'_, O> {
    fn call(
        &mut self,
        invocation: crate::InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        self.inner.call(invocation, module, operation, arguments)
    }

    fn declared_return(&self, module: &str, operation: &str) -> Option<String> {
        self.returns
            .get(&(module.to_owned(), operation.to_owned()))
            .cloned()
            .or_else(|| self.inner.declared_return(module, operation))
    }
}

/// What one handler did with one event.
#[derive(Debug)]
pub struct HandlerOutcome {
    /// The handler's event type (for a stream handler, the stream's name).
    pub handler: String,
    /// The value the body returned, or why it stopped.
    pub result: Result<Value, RuntimeError>,
}

/// The policy a checked program implies: every module operation the checker
/// validated is allowed, because the checker already required each one's
/// permission to be granted. This is the same rule `nscript run` applies to
/// top-level calls.
#[must_use]
pub fn policy_for(checked: &nscript_semantics::CheckedProgram) -> OperationPolicy {
    checked
        .operation_calls
        .iter()
        .fold(OperationPolicy::default(), |policy, call| {
            policy.allow(&call.module, &call.operation)
        })
}

fn within(inner: nscript_syntax::Span, outer: nscript_syntax::Span) -> bool {
    inner.start >= outer.start && inner.end <= outer.end
}

/// The operation calls a program makes at startup: every collected call except
/// those inside a handler body. The checker collects calls wherever they appear,
/// so without this a handler's `kick event.author` would run once at startup,
/// with its non-literal argument silently dropped.
///
/// `program` also excludes calls inside `fn` bodies, which run only when called.
#[must_use]
pub fn top_level_operation_calls<'a>(
    program: Option<&Program>,
    checked: &'a nscript_semantics::CheckedProgram,
) -> Vec<&'a nscript_semantics::CheckedOperationCall> {
    let mut deferred: Vec<nscript_syntax::Span> = checked
        .handlers
        .iter()
        .map(|handler| handler.span)
        .collect();
    if let Some(program) = program {
        deferred.extend(program.ast.items.iter().filter_map(|item| match item {
            Item::Function(function) => Some(function.span),
            _ => None,
        }));
    }
    checked
        .operation_calls
        .iter()
        .filter(|call| !deferred.iter().any(|span| within(call.span, *span)))
        .collect()
}

impl<R, S, C, A> Runtime<R, S, C, A>
where
    R: RelayHost,
    S: SignerHost,
    C: ClockHost,
    A: AuditHost,
{
    /// Delivers `event` to every handler whose subscription it matches and runs
    /// each body with the evaluator. A handler that fails does not stop the
    /// others, so one bad body cannot hide the rest.
    ///
    /// Handlers are matched by [`Runtime::matches_subscription`]: event type,
    /// author and tag predicates. Only the handlers that matched appear in the
    /// result.
    #[allow(clippy::too_many_arguments)]
    pub fn run_handlers_for_event<O: OperationHost, L: LogHost>(
        &mut self,
        program: &Program,
        checked: &nscript_semantics::CheckedProgram,
        event: &crate::SignedEvent,
        policy: &OperationPolicy,
        operations: &mut O,
        log: &mut L,
        principal: Option<&str>,
        limits: EvalLimits,
    ) -> Vec<HandlerOutcome> {
        let requests = Self::handler_subscriptions(checked, None);
        let mut outcomes = Vec::new();
        for (handler, request) in checked.handlers.iter().zip(&requests) {
            if !Self::matches_subscription(request, event) {
                continue;
            }
            let mut session = RuntimeSession {
                runtime: self,
                policy,
                operations,
                log,
                principal: principal.map(str::to_owned),
            };
            let result = settle(run_handler(
                program,
                &handler.body,
                Value::from_event(event),
                &mut session,
                limits,
            ));
            outcomes.push(HandlerOutcome {
                handler: handler.event_type.clone(),
                result,
            });
        }
        outcomes
    }
}

/// A handler that ran and failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerFailure {
    /// The handler's event type.
    pub handler: String,
    pub error: RuntimeError,
}

/// The result of one evaluated subscription cycle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CycleReport {
    /// Handlers that ran (a matching, unclaimed event), whether they succeeded
    /// or failed.
    pub dispatched: usize,
    /// The subset of `dispatched` that failed. A failure is reported here rather
    /// than aborting the cycle, so one bad body cannot hide the rest.
    pub failures: Vec<HandlerFailure>,
}

impl<R, S, C, A> Runtime<R, S, C, A>
where
    R: RelayHost,
    S: SignerHost,
    C: ClockHost,
    A: AuditHost,
{
    /// Dispatches one event to one handler with the evaluator, with the same
    /// discipline as [`Runtime::dispatch_checked_handler_transactional`]: the
    /// event must match the subscription, is claimed for idempotency, runs inside
    /// a storage transaction that commits only if the body succeeded, and is
    /// audited as `committed` or `rolled_back`.
    ///
    /// The idempotency claim is per handler *and* event (`handler_index` is the
    /// handler's position in the program), so redelivery to one handler is
    /// suppressed while a second handler on the same event still runs.
    ///
    /// `Ok(None)` means the handler did not run (no match, or the event was
    /// already claimed). `Ok(Some(result))` carries the body's outcome; a body
    /// failure is a value here, not an error, because the transaction has been
    /// rolled back and the caller decides what to do.
    ///
    /// # Errors
    ///
    /// Returns idempotency or storage failures, which prevent the body running.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_evaluated<I, T, L, O>(
        &mut self,
        program: &Program,
        request: &SubscriptionRequest,
        event: &crate::SignedEvent,
        handler_index: usize,
        handler: &nscript_semantics::CheckedHandler,
        policy: &OperationPolicy,
        idempotency_host: &mut I,
        storage_host: &mut T,
        log_host: &mut L,
        operations: &mut O,
        principal: Option<&str>,
        limits: EvalLimits,
    ) -> Result<Option<Result<Value, RuntimeError>>, RuntimeError>
    where
        I: IdempotencyHost,
        T: TransactionalStorageHost,
        L: LogHost,
        O: OperationHost,
    {
        if !Self::matches_subscription(request, event) {
            return Ok(None);
        }
        if !self.claim_once(idempotency_host, &format!("{handler_index}/{}", event.id))? {
            return Ok(None);
        }
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let transaction = storage_host.begin(invocation);
        let result = {
            let mut session = RuntimeSession {
                runtime: self,
                policy,
                operations,
                log: log_host,
                principal: principal.map(str::to_owned),
            };
            settle(run_handler(
                program,
                &handler.body,
                Value::from_event(event),
                &mut session,
                limits,
            ))
        };
        if result.is_ok() {
            storage_host.commit(transaction);
        }
        self.audit.record(AuditEntry {
            invocation,
            operation: "handler_transaction".to_owned(),
            target: event.id.clone(),
            result: if result.is_ok() {
                "committed"
            } else {
                "rolled_back"
            }
            .to_owned(),
        });
        Ok(Some(result))
    }

    /// Runs one subscription cycle: for each handler, subscribe, poll and
    /// dispatch each delivered event with the evaluator, then unsubscribe. This
    /// is [`Runtime::run_handler_cycle_with_event_body`] with the evaluator as the
    /// body engine, so a handler can call module operations.
    ///
    /// # Errors
    ///
    /// Returns subscription, polling, idempotency or storage failures. A handler
    /// body failure is reported in [`CycleReport::failures`] instead.
    #[allow(clippy::too_many_arguments)]
    pub fn run_evaluated_cycle<H, I, T, L, O>(
        &mut self,
        program: &Program,
        checked: &nscript_semantics::CheckedProgram,
        relayset: Option<&str>,
        subscription_host: &mut H,
        idempotency_host: &mut I,
        storage_host: &mut T,
        log_host: &mut L,
        operations: &mut O,
        principal: Option<&str>,
        limits: EvalLimits,
    ) -> Result<CycleReport, RuntimeError>
    where
        H: SubscriptionHost,
        I: IdempotencyHost,
        T: TransactionalStorageHost,
        L: LogHost,
        O: OperationHost,
    {
        let policy = policy_for(checked);
        let requests = Self::handler_subscriptions(checked, relayset);
        let mut report = CycleReport::default();
        for (index, (handler, request)) in checked.handlers.iter().zip(&requests).enumerate() {
            let handle = self.subscribe(subscription_host, request)?;
            let batch = match self.poll_subscription(subscription_host, &handle) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = self.unsubscribe(subscription_host, &handle);
                    return Err(error);
                }
            };
            for event in batch.events {
                let outcome = self.dispatch_evaluated(
                    program,
                    request,
                    &event,
                    index,
                    handler,
                    &policy,
                    idempotency_host,
                    storage_host,
                    log_host,
                    operations,
                    principal,
                    limits,
                );
                match outcome {
                    Ok(None) => {}
                    Ok(Some(Ok(_))) => report.dispatched += 1,
                    Ok(Some(Err(error))) => {
                        report.dispatched += 1;
                        report.failures.push(HandlerFailure {
                            handler: handler.event_type.clone(),
                            error,
                        });
                    }
                    Err(error) => {
                        let _ = self.unsubscribe(subscription_host, &handle);
                        return Err(error);
                    }
                }
            }
            self.unsubscribe(subscription_host, &handle)?;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FakeClock, FakeLogHost, FakeRelayHost, FakeSignerHost, InvocationId, RecordingAudit,
        SignedEvent, UnsignedEvent,
    };
    use nscript_syntax::parse_program;

    /// Records operation calls and answers with a canned value.
    #[derive(Default)]
    struct Recorder {
        printed: Vec<String>,
        calls: Vec<(String, String, Vec<OperationValue>)>,
        principal: Option<String>,
    }

    impl EvalHost for Recorder {
        fn print(&mut self, message: &str) -> Result<(), RuntimeError> {
            self.printed.push(message.to_owned());
            Ok(())
        }
        fn principal(&self) -> Option<String> {
            self.principal.clone()
        }
        fn call_operation(
            &mut self,
            module: &str,
            operation: &str,
            arguments: &[OperationValue],
        ) -> Result<OperationValue, RuntimeError> {
            self.calls
                .push((module.to_owned(), operation.to_owned(), arguments.to_vec()));
            Ok(OperationValue::Integer(1))
        }
    }

    fn event(content: &str) -> Value {
        Value::from_event(&SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "StreamMessage".to_owned(),
                kind: 9,
                content: content.to_owned(),
                tags: vec![("channel".to_owned(), "c1".to_owned())],
                created_at: 1_700_000_000,
            },
            signer: "author-key".to_owned(),
            id: "evt-1".to_owned(),
            signature: String::new(),
        })
    }

    /// Runs the body of the first `on` handler in `source` against `content`.
    fn run(source: &str, content: &str, host: &mut Recorder) -> Result<Value, RuntimeError> {
        let (program, diagnostics) = parse_program(source);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let body = program
            .ast
            .items
            .iter()
            .find_map(|item| match item {
                Item::Statement(statement) => match &statement.value {
                    StatementKind::On { body, .. } => Some(body.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("an `on` handler");
        run_handler(&program, &body, event(content), host, EvalLimits::default())
    }

    #[test]
    fn handlers_read_the_event_and_branch_on_it() {
        let mut host = Recorder::default();
        let source = "on messages {\n    if event.content contains \"spam\" {\n        print(\"spam from \" + event.author)\n    } else {\n        print(\"ok\")\n    }\n}\n";
        run(source, "buy spam now", &mut host).unwrap();
        run(source, "hello", &mut host).unwrap();
        assert_eq!(host.printed, ["spam from author-key", "ok"]);
    }

    #[test]
    fn a_handler_can_call_a_module_operation_with_a_value_from_the_event() {
        let mut host = Recorder::default();
        let source = "use concord04\non messages {\n    if event.content contains \"spam\" {\n        kick event.author\n    }\n}\n";
        run(source, "spam", &mut host).unwrap();
        run(source, "fine", &mut host).unwrap();
        assert_eq!(
            host.calls,
            vec![(
                "concord04".to_owned(),
                "kick_member".to_owned(),
                vec![OperationValue::PubKey("author-key".to_owned())]
            )],
            "only the spam message caused a kick, and the target is a typed PubKey"
        );
    }

    #[test]
    fn lets_arithmetic_comparison_and_short_circuit_work() {
        let mut host = Recorder::default();
        let source = "on m {\n    let n = 2 + 3 * 4\n    let long = len(event.content) > 3\n    if n == 14 and long {\n        print(\"yes\")\n    }\n    if false and missing == 1 {\n        print(\"never evaluated\")\n    }\n    if true or missing == 1 {\n        print(\"or short-circuits\")\n    }\n}\n";
        run(source, "hello", &mut host).unwrap();
        assert_eq!(host.printed, ["yes", "or short-circuits"]);
    }

    #[test]
    fn user_functions_recurse_return_and_see_only_their_parameters() {
        let mut host = Recorder::default();
        let source = "fn fact(n: Int) -> Int {\n    if n <= 1 {\n        return 1\n    }\n    return n * fact(n - 1)\n}\non m {\n    print(fact(5))\n}\n";
        run(source, "x", &mut host).unwrap();
        assert_eq!(host.printed, ["120"]);
        // A function cannot read the caller's names.
        let leaky = "fn f() -> Int {\n    return secret\n}\non m {\n    let secret = 1\n    print(f())\n}\n";
        let error = run(leaky, "x", &mut host).unwrap_err();
        assert!(
            matches!(error, RuntimeError::EvaluationError { ref message } if message.contains("unknown name `secret`"))
        );
    }

    #[test]
    fn loops_iterate_lists_and_event_tags_and_return_stops_the_handler() {
        let mut host = Recorder::default();
        let source = "on m {\n    for tag in event.tags {\n        print(tag)\n    }\n    for n in [1, 2, 3] {\n        if n == 2 {\n            return n\n        }\n        print(n)\n    }\n    print(\"unreached\")\n}\n";
        let value = run(source, "x", &mut host).unwrap();
        assert_eq!(value, Value::Int(2));
        assert_eq!(host.printed, ["channel=c1", "1"]);
    }

    #[test]
    fn me_is_the_principal_and_an_unconfigured_me_is_an_error() {
        let source = "on m {\n    print(me)\n}\n";
        let mut host = Recorder {
            principal: Some("my-key".to_owned()),
            ..Recorder::default()
        };
        run(source, "x", &mut host).unwrap();
        assert_eq!(host.printed, ["my-key"]);
        let error = run(source, "x", &mut Recorder::default()).unwrap_err();
        assert!(
            matches!(error, RuntimeError::EvaluationError { ref message } if message.contains("`me`"))
        );
    }

    #[test]
    fn a_record_built_in_a_handler_reaches_the_operation_as_a_typed_message() {
        let mut host = Recorder {
            principal: Some("my-key".to_owned()),
            ..Recorder::default()
        };
        let source = "use concord01\non m {\n    say \"pong\" in chat\n}\n";
        // `chat` is not bound in the handler: the source must come from the host.
        let error = run(source, "ping", &mut host).unwrap_err();
        assert!(
            matches!(error, RuntimeError::EvaluationError { ref message } if message.contains("unknown name `chat`"))
        );
        let bound = "use concord01\non m {\n    let chat = \"addr\"\n    say \"pong\" in chat\n}\n";
        run(bound, "ping", &mut host).unwrap();
        assert_eq!(
            host.calls[0].2[1],
            OperationValue::StreamMessage(StreamMessage {
                author: "my-key".to_owned(),
                content: "pong".to_owned()
            })
        );
    }

    #[test]
    fn runaway_and_bad_handlers_stop_with_stable_errors() {
        let mut host = Recorder::default();
        let deep = "fn f(n: Int) -> Int {\n    return f(n + 1)\n}\non m {\n    print(f(0))\n}\n";
        assert!(matches!(
            run(deep, "x", &mut host),
            Err(RuntimeError::ResourceLimit { ref resource }) if resource == "handler call depth"
        ));
        let long = "on m {\n    for a in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {\n        for b in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {\n            for c in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {\n                for d in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {\n                    for e in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {\n                        print(a)\n                    }\n                }\n            }\n        }\n    }\n}\n";
        assert!(matches!(
            run(long, "x", &mut host),
            Err(RuntimeError::ResourceLimit { ref resource }) if resource == "handler steps"
        ));
        for (source, needle) in [
            ("on m {\n    print(1 / 0)\n}\n", "division by zero"),
            (
                "on m {\n    if 1 {\n        print(1)\n    }\n}\n",
                "condition must be a bool",
            ),
            ("on m {\n    print(1 + \"a\")\n}\n", "needs two ints"),
            ("on m {\n    print(nope)\n}\n", "unknown name `nope`"),
            ("on m {\n    print(event.nope)\n}\n", "no field `nope`"),
        ] {
            let error = run(source, "x", &mut Recorder::default()).unwrap_err();
            assert!(
                matches!(&error, RuntimeError::EvaluationError { message } if message.contains(needle)),
                "{source:?}: {error:?}"
            );
        }
    }

    #[test]
    fn the_runtime_session_applies_the_operation_policy_inside_a_handler() {
        let source = "use concord04\non m {\n    kick event.author\n}\n";
        let (program, diagnostics) = parse_program(source);
        assert!(diagnostics.is_empty());
        let body = match &program.ast.items[1] {
            Item::Statement(statement) => match &statement.value {
                StatementKind::On { body, .. } => body.clone(),
                _ => panic!("handler"),
            },
            _ => panic!("statement"),
        };
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut log = FakeLogHost::default();
        let mut moderation = crate::moderation::ModerationHost::new("bot", {
            let mut roster = crate::authority::Roster::new("owner");
            roster.roles.insert(
                "mod".into(),
                crate::authority::Role {
                    role_id: "mod".into(),
                    position: 5,
                    permissions: crate::authority::perm::KICK,
                    server_scope: true,
                },
            );
            roster.grants.insert("bot".into(), vec!["mod".into()]);
            roster
        });
        let denied = OperationPolicy::default();
        let mut session = RuntimeSession {
            runtime: &mut runtime,
            policy: &denied,
            operations: &mut moderation,
            log: &mut log,
            principal: Some("bot".to_owned()),
        };
        let error = run_handler(
            &program,
            &body,
            event("x"),
            &mut session,
            EvalLimits::default(),
        )
        .unwrap_err();
        assert!(
            matches!(error, RuntimeError::CapabilityDenied { .. }),
            "{error:?}"
        );
        assert!(moderation.issued.is_empty());

        let allowed = OperationPolicy::default().allow("concord04", "kick_member");
        let mut session = RuntimeSession {
            runtime: &mut runtime,
            policy: &allowed,
            operations: &mut moderation,
            log: &mut log,
            principal: Some("bot".to_owned()),
        };
        run_handler(
            &program,
            &body,
            event("x"),
            &mut session,
            EvalLimits::default(),
        )
        .unwrap();
        assert_eq!(moderation.issued.len(), 1);
        let _: InvocationId = 0;
    }

    fn checked(source: &str) -> (nscript_syntax::Program, nscript_semantics::CheckedProgram) {
        let (program, diagnostics) = parse_program(source);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        (program, checked.expect("checks"))
    }

    const BOT: &str = "use concord04\n\npermissions {\n    concord_kick\n    log\n}\n\non Note {\n    if event.content contains \"spam\" {\n        print(\"kicking \" + event.author)\n        kick event.author\n    }\n}\n";

    fn runtime() -> Runtime<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit> {
        Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        )
    }

    #[test]
    fn events_are_built_from_json_with_defaults_and_an_author_alias() {
        let event = event_from_json(
            &serde_json::json!({"content": "hi", "author": "bob", "tags": [["t", "nostr"], ["p"]]}),
        )
        .unwrap();
        assert_eq!(event.unsigned.event_type, "Note");
        assert_eq!(
            (event.unsigned.kind, event.unsigned.content.as_str()),
            (1, "hi")
        );
        assert_eq!(event.signer, "bob");
        assert_eq!(
            event.unsigned.tags,
            vec![
                ("t".to_owned(), "nostr".to_owned()),
                ("p".to_owned(), String::new())
            ]
        );
        assert!(event_from_json(&serde_json::json!([1])).is_err());
        assert!(event_from_json(&serde_json::json!({"kind": 70000})).is_err());
    }

    #[test]
    fn the_simulator_runs_what_the_fake_host_knows_and_answers_the_rest_by_declared_type() {
        let mut ops = SimulatedOperations::new(BTreeMap::from([
            (
                ("concord04".to_owned(), "kick_member".to_owned()),
                "Result<PublishReport,ModerationError>".to_owned(),
            ),
            (
                ("concord04".to_owned(), "can_kick".to_owned()),
                "Result<Int,ModerationError>".to_owned(),
            ),
        ]));
        let target = [OperationValue::PubKey("alice".to_owned())];
        let kicked = ops.call(1, "concord04", "kick_member", &target).unwrap();
        assert!(matches!(kicked, OperationValue::PublishReport(ref r) if r.accepted()));
        assert_eq!(
            ops.call(1, "concord04", "can_kick", &target).unwrap(),
            OperationValue::Integer(0)
        );
        // A real fake-host operation is executed, not simulated.
        ops.call(
            1,
            "nip44",
            "encrypt_text",
            &[
                OperationValue::Text("x".to_owned()),
                OperationValue::PubKey("alice".to_owned()),
            ],
        )
        .unwrap();
        let flags: Vec<_> = ops
            .calls
            .iter()
            .map(|c| (c.operation.as_str(), c.simulated))
            .collect();
        assert_eq!(
            flags,
            [
                ("kick_member", true),
                ("can_kick", true),
                ("encrypt_text", false)
            ]
        );
        // A wrong argument shape to a known operation is a real failure.
        let bad = ops.call(1, "nip44", "encrypt_text", &[]);
        assert!(matches!(
            bad,
            Err(RuntimeError::InvalidOperationArguments { .. })
        ));
    }

    #[test]
    fn handler_and_function_calls_are_not_startup_calls() {
        let source = "use concord04\n\npermissions {\n    concord_kick\n    log\n}\n\nfn helper() {\n    concord04.kick_member(alice)\n}\n\nconcord04.kick_member(bob)\n\non Note {\n    kick event.author\n}\n";
        let (program, checked) = checked(source);
        assert_eq!(
            checked.operation_calls.len(),
            3,
            "the checker collects every call"
        );
        assert_eq!(
            top_level_operation_calls(None, &checked).len(),
            2,
            "handlers excluded"
        );
        let top = top_level_operation_calls(Some(&program), &checked);
        assert_eq!(top.len(), 1, "functions excluded too");
        assert_eq!(
            top[0].arguments,
            vec![nscript_semantics::CheckedArgument::PubKey("bob".to_owned())]
        );
    }

    #[test]
    fn an_event_reaches_only_the_handlers_it_matches_and_the_bot_acts() {
        let (program, checked) = checked(BOT);
        let mut ops = SimulatedOperations::new(BTreeMap::new());
        let mut log = FakeLogHost::default();
        let mut runtime = runtime();
        let policy = policy_for(&checked);
        let spam =
            event_from_json(&serde_json::json!({"content": "buy spam", "signer": "mallory"}))
                .unwrap();
        let outcomes = runtime.run_handlers_for_event(
            &program,
            &checked,
            &spam,
            &policy,
            &mut ops,
            &mut log,
            None,
            EvalLimits::default(),
        );
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].result.is_ok());
        assert_eq!(log.records[0].message, "kicking mallory");
        assert_eq!(ops.calls.len(), 1);
        assert_eq!(
            ops.calls[0].arguments,
            vec![OperationValue::PubKey("mallory".to_owned())]
        );

        // Not spam: the handler runs and does nothing.
        let fine = event_from_json(&serde_json::json!({"content": "hello"})).unwrap();
        let outcomes = runtime.run_handlers_for_event(
            &program,
            &checked,
            &fine,
            &policy,
            &mut ops,
            &mut log,
            None,
            EvalLimits::default(),
        );
        assert_eq!(outcomes.len(), 1);
        assert_eq!(ops.calls.len(), 1, "no further call");
        // A different event type matches no handler.
        let other =
            event_from_json(&serde_json::json!({"event_type": "Reaction", "content": "spam"}))
                .unwrap();
        assert!(
            runtime
                .run_handlers_for_event(
                    &program,
                    &checked,
                    &other,
                    &policy,
                    &mut ops,
                    &mut log,
                    None,
                    EvalLimits::default()
                )
                .is_empty()
        );
    }

    #[test]
    fn one_failing_handler_does_not_hide_the_others() {
        let source = "permissions {\n    log\n}\n\non Note {\n    print(nope)\n}\n\non Note {\n    print(\"second ran\")\n}\n";
        let (program, checked) = checked(source);
        let mut log = FakeLogHost::default();
        let mut ops = SimulatedOperations::new(BTreeMap::new());
        let event = event_from_json(&serde_json::json!({})).unwrap();
        let outcomes = runtime().run_handlers_for_event(
            &program,
            &checked,
            &event,
            &policy_for(&checked),
            &mut ops,
            &mut log,
            None,
            EvalLimits::default(),
        );
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(
            outcomes[0].result,
            Err(RuntimeError::EvaluationError { .. })
        ));
        assert!(outcomes[1].result.is_ok());
        assert_eq!(log.records.len(), 1);
    }

    /// What one evaluated cycle produced.
    struct CycleRun {
        report: Result<CycleReport, RuntimeError>,
        ops: SimulatedOperations,
        log: FakeLogHost,
        /// `(event id, "committed" | "rolled_back")` per dispatched handler.
        audit: Vec<(String, String)>,
    }

    fn cycle(source: &str, events: &[crate::SignedEvent]) -> CycleRun {
        let (program, checked) = checked(source);
        let mut relay = FakeRelayHost::default();
        // The cycle subscribes once per handler; give every handle the events.
        for handle in 1..=checked.handlers.len() {
            relay.queued_events.insert(handle as u64, events.to_vec());
        }
        let mut claims = crate::InMemoryStorage::default();
        let mut storage = crate::InMemoryStorage::default();
        let mut log = FakeLogHost::default();
        let mut ops = SimulatedOperations::new(BTreeMap::new());
        let mut runtime = runtime();
        let report = runtime.run_evaluated_cycle(
            &program,
            &checked,
            Some("public"),
            &mut relay,
            &mut claims,
            &mut storage,
            &mut log,
            &mut ops,
            None,
            EvalLimits::default(),
        );
        let audit = runtime
            .audit
            .entries
            .iter()
            .filter(|entry| entry.operation == "handler_transaction")
            .map(|entry| (entry.target.clone(), entry.result.clone()))
            .collect();
        CycleRun {
            report,
            ops,
            log,
            audit,
        }
    }

    fn note(id: &str, content: &str) -> crate::SignedEvent {
        event_from_json(&serde_json::json!({"id": id, "content": content, "signer": "mallory"}))
            .unwrap()
    }

    #[test]
    fn a_cycle_runs_the_handler_and_commits_its_transaction() {
        let run = cycle(BOT, &[note("e1", "spam")]);
        let (ops, log, audit) = (run.ops, run.log, run.audit);
        let report = run.report.unwrap();
        assert_eq!((report.dispatched, report.failures.len()), (1, 0));
        assert_eq!(log.records[0].message, "kicking mallory");
        assert_eq!(ops.calls.len(), 1, "the handler called a module operation");
        assert_eq!(audit, [("e1".to_owned(), "committed".to_owned())]);
    }

    #[test]
    fn a_redelivered_event_runs_once() {
        let run = cycle(BOT, &[note("same", "spam"), note("same", "spam")]);
        let (ops, audit) = (run.ops, run.audit);
        assert_eq!(run.report.unwrap().dispatched, 1);
        assert_eq!(ops.calls.len(), 1, "the duplicate was claimed and skipped");
        assert_eq!(audit.len(), 1);
    }

    #[test]
    fn a_failing_handler_rolls_back_is_reported_and_does_not_hide_the_next() {
        let source = "permissions {\n    log\n}\n\non Note {\n    print(nope)\n}\n\non Note {\n    print(\"second ran\")\n}\n";
        let run = cycle(source, &[note("e1", "x")]);
        let (log, audit) = (run.log, run.audit);
        let report = run.report.unwrap();
        assert_eq!(report.dispatched, 2, "both handlers ran");
        assert_eq!(report.failures.len(), 1);
        assert!(
            matches!(&report.failures[0].error, RuntimeError::EvaluationError { message } if message.contains("nope"))
        );
        assert_eq!(log.records.len(), 1);
        // The failed body's transaction was rolled back; the other committed.
        assert_eq!(
            audit,
            [
                ("e1".to_owned(), "rolled_back".to_owned()),
                ("e1".to_owned(), "committed".to_owned())
            ]
        );
    }

    #[test]
    fn an_event_that_matches_no_handler_dispatches_nothing() {
        let other =
            event_from_json(&serde_json::json!({"id": "r", "event_type": "Reaction"})).unwrap();
        let run = cycle(BOT, &[other]);
        let (ops, audit) = (run.ops, run.audit);
        assert_eq!(run.report.unwrap(), CycleReport::default());
        assert!(ops.calls.is_empty() && audit.is_empty());
    }

    #[test]
    fn two_handlers_on_one_event_both_run_in_the_original_cycle_too() {
        // Two handlers subscribed to the same events used to starve the second:
        // the poll dedupe and the idempotency claim were both keyed by event id
        // alone, so the first handler consumed it.
        let source = "permissions {\n    log\n}\n\non Note {\n    print(\"first\")\n}\n\non Note {\n    print(\"second\")\n}\n";
        let (_, checked) = checked(source);
        let mut relay = FakeRelayHost::default();
        for handle in 1..=2 {
            relay.queued_events.insert(handle, vec![note("e1", "x")]);
        }
        let mut claims = crate::InMemoryStorage::default();
        let mut storage = crate::InMemoryStorage::default();
        let mut log = FakeLogHost::default();
        let dispatched = runtime()
            .run_handler_cycle_with_event_body(
                &checked,
                Some("public"),
                &mut relay,
                &mut claims,
                &mut storage,
                &mut log,
            )
            .unwrap();
        assert_eq!(dispatched, 2);
        let messages: Vec<_> = log.records.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(messages, ["first", "second"]);
    }

    /// A host whose `concord04` operations succeed or fail on demand and declare
    /// their return type (or not).
    #[derive(Default)]
    struct Scripted {
        printed: Vec<String>,
        fail_with: Option<RuntimeError>,
        declared: Option<&'static str>,
        calls: usize,
    }

    impl EvalHost for Scripted {
        fn print(&mut self, message: &str) -> Result<(), RuntimeError> {
            self.printed.push(message.to_owned());
            Ok(())
        }
        fn principal(&self) -> Option<String> {
            Some("me-key".to_owned())
        }
        fn call_operation(
            &mut self,
            _module: &str,
            _operation: &str,
            _arguments: &[OperationValue],
        ) -> Result<OperationValue, RuntimeError> {
            self.calls += 1;
            match &self.fail_with {
                Some(error) => Err(error.clone()),
                None => Ok(OperationValue::PublishReport(crate::PublishReport {
                    outcomes: vec![crate::RelayOutcome {
                        relay: "r".to_owned(),
                        accepted: true,
                        detail: String::new(),
                    }],
                })),
            }
        }
        fn declared_return(&self, _module: &str, _operation: &str) -> Option<String> {
            self.declared.map(str::to_owned)
        }
    }

    const RESULT_TYPE: &str = "Result<PublishReport,ModerationError>";

    fn scripted(fail_with: Option<RuntimeError>) -> Scripted {
        Scripted {
            declared: Some(RESULT_TYPE),
            fail_with,
            ..Scripted::default()
        }
    }

    fn denied() -> RuntimeError {
        RuntimeError::AuthorityDenied {
            actor: "bot".to_owned(),
            action: "kick".to_owned(),
        }
    }

    /// Runs the first handler of `source` against `host`, returning the raw
    /// value (a `?`-propagated error is `Ok(Value::ResultErr(..))`).
    fn run_scripted(source: &str, host: &mut Scripted) -> Result<Value, RuntimeError> {
        let (program, diagnostics) = parse_program(source);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let body = program
            .ast
            .items
            .iter()
            .find_map(|item| match item {
                Item::Statement(statement) => match &statement.value {
                    StatementKind::On { body, .. } => Some(body.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("an `on` handler");
        run_handler(&program, &body, event("x"), host, EvalLimits::default())
    }

    const BRANCHING_BOT: &str = "use concord04\non m {\n    match concord04.kick_member(event.author) {\n        Ok(report) => print(\"kicked\")\n        Err(error) => print(\"could not kick: \" + error.message)\n    }\n}\n";

    #[test]
    fn a_handler_can_branch_on_a_successful_operation_result() {
        let mut host = scripted(None);
        run_scripted(BRANCHING_BOT, &mut host).unwrap();
        assert_eq!(host.printed, ["kicked"]);
        // The success payload is the operation's value.
        let source = "use concord04\non m {\n    match concord04.kick_member(event.author) {\n        Ok(report) => print(report.accepted)\n        Err(e) => print(\"no\")\n    }\n}\n";
        let mut host = scripted(None);
        run_scripted(source, &mut host).unwrap();
        assert_eq!(host.printed, ["true"]);
    }

    #[test]
    fn a_recoverable_failure_becomes_an_error_value_the_script_can_read() {
        let mut host = scripted(Some(denied()));
        run_scripted(BRANCHING_BOT, &mut host).unwrap();
        assert_eq!(host.printed, ["could not kick: not authorized to kick"]);
        for recoverable in [
            RuntimeError::RelayUnavailable {
                relayset: "r".to_owned(),
            },
            RuntimeError::PublicationRejected,
            RuntimeError::StoreConflict,
            RuntimeError::SignerDenied {
                signer: "s".to_owned(),
            },
            RuntimeError::PaymentLimitExceeded {
                amount: 5,
                limit: 1,
            },
        ] {
            let mut host = scripted(Some(recoverable));
            run_scripted(BRANCHING_BOT, &mut host).unwrap();
            assert!(
                host.printed[0].starts_with("could not kick: "),
                "{:?}",
                host.printed
            );
        }
    }

    #[test]
    fn a_failure_that_is_not_the_operations_to_report_still_aborts() {
        // A script must not be able to catch a permission boundary or its own
        // programming mistake.
        for fatal in [
            RuntimeError::CapabilityDenied {
                capability: "concord04.kick_member".to_owned(),
            },
            RuntimeError::InvalidOperationArguments {
                operation: "kick_member".to_owned(),
            },
            RuntimeError::OperationUnavailable {
                module: "m".to_owned(),
                operation: "o".to_owned(),
            },
            RuntimeError::ResourceLimit {
                resource: "x".to_owned(),
            },
        ] {
            let mut host = scripted(Some(fatal.clone()));
            assert_eq!(run_scripted(BRANCHING_BOT, &mut host), Err(fatal));
            assert!(host.printed.is_empty(), "no arm ran");
        }
    }

    #[test]
    fn question_mark_returns_the_error_from_the_handler_and_skips_the_rest() {
        let source = "use concord04\non m {\n    let report = concord04.kick_member(event.author)?\n    print(\"after\")\n}\n";
        let mut host = scripted(Some(denied()));
        let value = run_scripted(source, &mut host).unwrap();
        assert!(
            matches!(&value, Value::ResultErr(error) if error.display().contains("not authorized to kick")),
            "{value:?}"
        );
        assert!(
            host.printed.is_empty(),
            "the statement after `?` did not run"
        );
        // The evaluator settles that into a handler failure, so it rolls back.
        let settled = settle(Ok(value));
        assert!(
            matches!(settled, Err(RuntimeError::HandlerError { ref message }) if message.contains("ModerationError"))
        );
        // On success `?` unwraps and the handler carries on.
        let mut host = scripted(None);
        run_scripted(source, &mut host).unwrap();
        assert_eq!(host.printed, ["after"]);
    }

    #[test]
    fn question_mark_in_a_function_returns_the_error_from_that_function() {
        let source = "use concord04\nfn try_kick(who: PubKey) -> Result<Int, ModerationError> {\n    let report = concord04.kick_member(who)?\n    return Ok(1)\n}\non m {\n    match try_kick(event.author) {\n        Ok(n) => print(\"ok\")\n        Err(e) => print(\"failed: \" + e.message)\n    }\n    print(\"handler continued\")\n}\n";
        let mut host = scripted(Some(denied()));
        run_scripted(source, &mut host).unwrap();
        assert_eq!(
            host.printed,
            ["failed: not authorized to kick", "handler continued"]
        );
        let mut host = scripted(None);
        run_scripted(source, &mut host).unwrap();
        assert_eq!(host.printed, ["ok", "handler continued"]);
    }

    #[test]
    fn hosts_that_do_not_declare_types_keep_plain_values() {
        // No declared return type: no Result wrapping, so existing scripts that
        // read the value directly, and a `?` on a plain value, are unchanged.
        let source = "use concord04\non m {\n    let report = concord04.kick_member(event.author)?\n    print(report.accepted)\n}\n";
        let mut host = Scripted::default();
        run_scripted(source, &mut host).unwrap();
        assert_eq!(host.printed, ["true"]);
        // Without a declared type a failure aborts, as before.
        let mut host = Scripted {
            fail_with: Some(denied()),
            ..Scripted::default()
        };
        assert_eq!(run_scripted(source, &mut host), Err(denied()));
    }

    #[test]
    fn match_binds_nests_and_falls_through_to_a_catch_all() {
        // Only the pattern forms the parser produces: variants, bindings, `_`.
        let source = "on m {\n    match Ok(3) {\n        Err(e) => print(\"err\")\n        Ok(n) => print(n)\n    }\n    match Ok(Err(\"deep\")) {\n        Ok(Ok(v)) => print(\"no\")\n        Ok(Err(e)) => print(e)\n        _ => print(\"other\")\n    }\n    match Err(1) {\n        Ok(v) => print(\"no\")\n        other => print(other)\n    }\n}\n";
        let mut host = Scripted::default();
        run_scripted(source, &mut host).unwrap();
        assert_eq!(host.printed, ["3", "deep", "Err(1)"]);
    }

    fn pat(kind: PatternKind) -> nscript_syntax::ast::Pattern {
        nscript_syntax::ast::Spanned {
            value: kind,
            span: nscript_syntax::Span::default(),
        }
    }

    /// The parser does not yet produce literal, record or guarded patterns
    /// (the spec's section 10 uses them), but the AST has them, so the evaluator
    /// must handle them correctly for when it does. Tested on hand-built AST.
    #[test]
    fn literal_and_record_patterns_are_handled_though_the_parser_cannot_yet_produce_them() {
        let mut bound = BTreeMap::new();
        let matches = |kind: &PatternKind, value: &Value, bound: &mut BTreeMap<String, Value>| {
            pattern_matches(kind, value, bound)
        };
        assert!(matches(
            &PatternKind::Literal(ExprKind::Integer(1)),
            &Value::Int(1),
            &mut bound
        ));
        assert!(!matches(
            &PatternKind::Literal(ExprKind::Integer(1)),
            &Value::Int(2),
            &mut bound
        ));
        assert!(matches(
            &PatternKind::Literal(ExprKind::Text("a".into())),
            &Value::PubKey("a".into()),
            &mut bound
        ));
        assert!(matches(
            &PatternKind::Literal(ExprKind::Bool(true)),
            &Value::Bool(true),
            &mut bound
        ));
        assert!(!matches(
            &PatternKind::Literal(ExprKind::Text("a".into())),
            &Value::Int(1),
            &mut bound
        ));

        let message = Value::Record {
            name: "Note".into(),
            fields: vec![
                ("author".into(), Value::PubKey("alice".into())),
                ("content".into(), Value::Text("hi".into())),
            ],
        };
        // `Note { author, content: c }`: shorthand binds the field's own name.
        let record = PatternKind::Record {
            name: "Note".into(),
            fields: vec![
                ("author".into(), None),
                (
                    "content".into(),
                    Some(pat(PatternKind::Binding("c".into()))),
                ),
            ],
        };
        assert!(matches(&record, &message, &mut bound));
        assert_eq!(bound["author"], Value::PubKey("alice".into()));
        assert_eq!(bound["c"], Value::Text("hi".into()));
        let wrong_name = PatternKind::Record {
            name: "Other".into(),
            fields: vec![],
        };
        assert!(!matches(&wrong_name, &message, &mut BTreeMap::new()));
        let missing_field = PatternKind::Record {
            name: "Note".into(),
            fields: vec![("nope".into(), None)],
        };
        assert!(!matches(&missing_field, &message, &mut BTreeMap::new()));
    }

    /// A guard picks between arms that share a pattern.
    #[test]
    fn a_guard_picks_between_arms_though_the_parser_cannot_yet_produce_one() {
        let (program, _) = parse_program("on m {\n}\n");
        let mut host = Scripted::default();
        let mut interpreter = Interpreter {
            host: &mut host,
            functions: BTreeMap::new(),
            modules: BTreeSet::new(),
            scopes: vec![BTreeMap::new()],
            limits: EvalLimits::default(),
            steps: 0,
            depth: 0,
        };
        let _ = &program;
        let text = |value: &str| nscript_syntax::ast::Spanned {
            value: ExprKind::Text(value.to_owned()),
            span: nscript_syntax::Span::default(),
        };
        let name = |value: &str| nscript_syntax::ast::Spanned {
            value: ExprKind::Identifier(value.to_owned()),
            span: nscript_syntax::Span::default(),
        };
        let greater = nscript_syntax::ast::Spanned {
            value: ExprKind::Binary {
                operator: ">".to_owned(),
                left: Box::new(name("n")),
                right: Box::new(nscript_syntax::ast::Spanned {
                    value: ExprKind::Integer(5),
                    span: nscript_syntax::Span::default(),
                }),
            },
            span: nscript_syntax::Span::default(),
        };
        let arms = [
            MatchArm {
                pattern: pat(PatternKind::Binding("n".into())),
                guard: Some(greater),
                value: text("big"),
            },
            MatchArm {
                pattern: pat(PatternKind::Wildcard),
                guard: None,
                value: text("small"),
            },
        ];
        let subject = |n: i64| nscript_syntax::ast::Spanned {
            value: ExprKind::Integer(n),
            span: nscript_syntax::Span::default(),
        };
        assert_eq!(
            interpreter.match_expression(&subject(9), &arms).ok(),
            Some(Value::Text("big".into()))
        );
        assert_eq!(
            interpreter.match_expression(&subject(2), &arms).ok(),
            Some(Value::Text("small".into()))
        );
    }

    #[test]
    fn a_match_no_arm_covers_is_an_error_not_a_silent_fall_through() {
        // The checker cannot see the type of a call's result, so an arm that
        // handles only `Ok` passes `check`; at run time it must not be ignored.
        let source = "use concord04\non m {\n    match concord04.kick_member(event.author) {\n        Ok(report) => print(\"ok\")\n    }\n}\n";
        let mut host = scripted(Some(denied()));
        let error = run_scripted(source, &mut host).unwrap_err();
        assert!(
            matches!(error, RuntimeError::EvaluationError { ref message } if message.contains("no `match` arm")),
            "{error:?}"
        );
    }

    #[test]
    fn ok_and_err_are_values_scripts_can_build_and_return() {
        let source = "on m {\n    let a = Ok(2)\n    let b = Err(\"bad\")\n    match a {\n        Ok(n) => print(n + 1)\n        Err(e) => print(\"e\")\n    }\n    match b {\n        Ok(n) => print(\"o\")\n        Err(e) => print(\"err \" + e)\n    }\n    return Err(\"stop\")\n}\n";
        let mut host = Scripted::default();
        let value = run_scripted(source, &mut host).unwrap();
        assert_eq!(host.printed, ["3", "err bad"]);
        assert_eq!(
            value,
            Value::ResultErr(Box::new(Value::Text("stop".to_owned())))
        );
        // A result cannot be passed to an operation without being unwrapped.
        let bad = "use concord04\non m {\n    concord04.kick_member(Ok(1))\n}\n";
        let error = run_scripted(bad, &mut Scripted::default()).unwrap_err();
        assert!(
            matches!(error, RuntimeError::EvaluationError { ref message } if message.contains("cannot pass a result")),
            "{error:?}"
        );
    }

    #[test]
    fn declared_result_types_are_parsed_at_the_top_level_comma() {
        assert_eq!(
            result_error_type("Result<PublishReport,ModerationError>").as_deref(),
            Some("ModerationError")
        );
        assert_eq!(
            result_error_type("Result<List<Note>, RelayError>").as_deref(),
            Some("RelayError")
        );
        assert_eq!(
            result_error_type("Result<Map<A,B>,E>").as_deref(),
            Some("E")
        );
        assert_eq!(result_error_type("PublishReport"), None);
        assert_eq!(result_error_type("Result<OnlyOne>"), None);
    }

    #[test]
    fn a_handler_that_returns_an_error_rolls_back_and_is_reported_in_a_cycle() {
        let source = "use concord04\n\npermissions {\n    concord_kick\n}\n\non Note {\n    let report = concord04.kick_member(event.author)?\n}\n";
        let (program, checked) = checked(source);
        let mut ops = SimulatedOperations::new(BTreeMap::from([(
            ("concord04".to_owned(), "kick_member".to_owned()),
            RESULT_TYPE.to_owned(),
        )]));
        ops.fail_operation("concord04", "kick_member");
        let mut relay = FakeRelayHost::default();
        relay.queued_events.insert(1, vec![note("e1", "x")]);
        let mut claims = crate::InMemoryStorage::default();
        let mut storage = crate::InMemoryStorage::default();
        let mut log = FakeLogHost::default();
        let mut runtime = runtime();
        let report = runtime
            .run_evaluated_cycle(
                &program,
                &checked,
                Some("public"),
                &mut relay,
                &mut claims,
                &mut storage,
                &mut log,
                &mut ops,
                None,
                EvalLimits::default(),
            )
            .unwrap();
        assert_eq!(report.failures.len(), 1);
        assert!(
            matches!(&report.failures[0].error, RuntimeError::HandlerError { message } if message.contains("publication rejected")),
            "{:?}",
            report.failures
        );
        assert_eq!(ops.calls.len(), 1, "the attempt was recorded");
        let audit: Vec<_> = runtime
            .audit
            .entries
            .iter()
            .filter(|e| e.operation == "handler_transaction")
            .map(|e| e.result.as_str())
            .collect();
        assert_eq!(audit, ["rolled_back"]);
    }
}
