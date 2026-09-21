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
use nscript_syntax::ast::{Expr, ExprKind, FunctionDeclaration, Item, StatementKind};

use crate::{
    AuditHost, ClockHost, LogHost, LogRecord, OperationHost, OperationPolicy, OperationValue,
    RelayHost, Runtime, RuntimeError, SignerHost, StreamMessage,
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
            Self::Op(value) => format!("{value:?}"),
        }
    }

    /// The delivered event as a handler sees it.
    #[must_use]
    pub fn from_event(event: &crate::SignedEvent) -> Self {
        Self::Record {
            name: "Event".to_owned(),
            fields: vec![
                ("id".to_owned(), Self::Text(event.id.clone())),
                ("author".to_owned(), Self::PubKey(event.signer.clone())),
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

    fn to_operation(&self) -> Result<OperationValue, RuntimeError> {
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
                    .collect::<Result<_, RuntimeError>>()?,
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

fn fail(message: impl Into<String>) -> RuntimeError {
    RuntimeError::EvaluationError {
        message: message.into(),
    }
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
    match interpreter.block(body)? {
        Flow::Return(value) => Ok(value),
        Flow::Next => Ok(Value::Unit),
    }
}

impl<H: EvalHost> Interpreter<'_, H> {
    fn step(&mut self) -> Result<(), RuntimeError> {
        self.steps += 1;
        if self.steps > self.limits.max_steps {
            return Err(RuntimeError::ResourceLimit {
                resource: "handler steps".to_owned(),
            });
        }
        Ok(())
    }

    fn block(&mut self, items: &[Item]) -> Result<Flow, RuntimeError> {
        self.scopes.push(BTreeMap::new());
        let result = self.items(items);
        self.scopes.pop();
        result
    }

    fn items(&mut self, items: &[Item]) -> Result<Flow, RuntimeError> {
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

    fn statement(&mut self, statement: &StatementKind) -> Result<Flow, RuntimeError> {
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

    fn condition(&mut self, expression: &Expr) -> Result<bool, RuntimeError> {
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

    fn expression(&mut self, expression: &Expr) -> Result<Value, RuntimeError> {
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
                    .collect::<Result<_, RuntimeError>>()?,
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
            // Operation failures already abort the handler, so `?` is a no-op
            // on the success path.
            ExprKind::Propagate(value) => self.expression(value),
            ExprKind::Call { callee, arguments } => self.call(callee, arguments),
            other => Err(unsupported(
                &format!("{other:?}").chars().take(24).collect::<String>(),
            )),
        }
    }

    fn identifier(&self, name: &str) -> Result<Value, RuntimeError> {
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

    fn unary(&mut self, operator: &str, value: &Expr) -> Result<Value, RuntimeError> {
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

    fn binary(&mut self, operator: &str, left: &Expr, right: &Expr) -> Result<Value, RuntimeError> {
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

    fn call(&mut self, callee: &Expr, arguments: &[Expr]) -> Result<Value, RuntimeError> {
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
                let result = self.host.call_operation(module, &name.value, &operands)?;
                Ok(Value::from_operation(result))
            }
            _ => Err(fail("this call is not supported")),
        }
    }

    fn call_function(&mut self, name: &str, arguments: Vec<Value>) -> Result<Value, RuntimeError> {
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
            });
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
        match result? {
            Flow::Return(value) => Ok(value),
            Flow::Next => Ok(Value::Unit),
        }
    }
}

fn unsupported(what: &str) -> RuntimeError {
    RuntimeError::OperationUnavailable {
        module: "handler".to_owned(),
        operation: what.to_owned(),
    }
}

/// Equality across the text-like kinds: a `PubKey` written as a literal is
/// text, so the two compare by their characters.
fn same(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Text(a) | Value::PubKey(a), Value::Text(b) | Value::PubKey(b)) => a == b,
        _ => left == right,
    }
}

fn contains(haystack: &Value, needle: &Value) -> Result<bool, RuntimeError> {
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

fn compare(operator: &str, left: &Value, right: &Value) -> Result<bool, RuntimeError> {
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

fn arithmetic(operator: &str, left: &Value, right: &Value) -> Result<Value, RuntimeError> {
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
#[derive(Clone, Debug, PartialEq)]
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
    pub calls: Vec<SimulatedCall>,
}

impl SimulatedOperations {
    #[must_use]
    pub fn new(returns: BTreeMap<(String, String), String>) -> Self {
        Self {
            fake: crate::FakeOperationHost::default(),
            returns,
            calls: Vec::new(),
        }
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
            let result = run_handler(
                program,
                &handler.body,
                Value::from_event(event),
                &mut session,
                limits,
            );
            outcomes.push(HandlerOutcome {
                handler: handler.event_type.clone(),
                result,
            });
        }
        outcomes
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
}
