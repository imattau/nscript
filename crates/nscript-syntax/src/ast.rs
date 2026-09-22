use crate::{Import, RuntimeProfile, Span};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AstProgram {
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Span,
}

pub type Expr = Spanned<ExprKind>;
pub type Statement = Spanned<StatementKind>;
pub type Pattern = Spanned<PatternKind>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Item {
    Use(Import),
    Runtime(Spanned<RuntimeProfile>),
    Defaults {
        signer: Option<Spanned<String>>,
        relays: Option<Spanned<String>>,
        span: Span,
    },
    Let(LetDeclaration),
    Function(FunctionDeclaration),
    Event(EventDeclaration),
    Signer(CapabilityDeclaration),
    Relay(CapabilityDeclaration),
    RelaySet(CapabilityDeclaration),
    /// `key name = host("label")`: a key the host holds, bound to a name.
    Key(CapabilityDeclaration),
    Store(StoreDeclaration),
    Permissions(Spanned<Vec<Permission>>),
    Stream {
        name: Spanned<String>,
        value: Expr,
        span: Span,
    },
    Statement(Statement),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LetDeclaration {
    pub name: Spanned<String>,
    pub type_annotation: Option<TypeRef>,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionDeclaration {
    pub name: Spanned<String>,
    pub parameters: Vec<Parameter>,
    pub return_type: Option<TypeRef>,
    pub body: Vec<Item>,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parameter {
    pub name: Spanned<String>,
    pub type_ref: TypeRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDeclaration {
    pub name: Spanned<String>,
    pub kind: Option<u16>,
    pub mode: EventModeSyntax,
    pub parameter: Option<Spanned<String>>,
    pub fields: Vec<EventField>,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventModeSyntax {
    #[default]
    Regular,
    Replaceable,
    Parameterised,
    Ephemeral,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventField {
    pub name: Spanned<String>,
    pub type_ref: TypeRef,
    pub default: Option<Expr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityDeclaration {
    pub name: Spanned<String>,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreDeclaration {
    pub name: Spanned<String>,
    pub key_type: Option<TypeRef>,
    pub value_type: TypeRef,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Permission {
    Read {
        event: TypeRef,
        relayset: Option<Spanned<String>>,
    },
    Publish {
        event: TypeRef,
        relayset: Option<Spanned<String>>,
    },
    Sign {
        event: TypeRef,
        signer: Option<Spanned<String>>,
    },
    Typed {
        operation: Spanned<String>,
        target: TypeRef,
        capability: Option<Spanned<String>>,
    },
    Named {
        operation: Spanned<String>,
        argument: Option<Spanned<String>>,
        /// `in <scope>` (RFC 0002 §2), e.g. `concord Kick in devs`. Only the
        /// `concord` namespace parses this today.
        scope: Option<Spanned<String>>,
    },
    Http(Spanned<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatementKind {
    Expression(Expr),
    Return(Option<Expr>),
    For {
        binding: Spanned<String>,
        value: Expr,
        body: Vec<Item>,
    },
    If {
        condition: Expr,
        then_body: Vec<Item>,
        else_body: Vec<Item>,
    },
    On {
        source: Expr,
        predicate: Option<Expr>,
        body: Vec<Item>,
    },
    Once {
        key: Expr,
        body: Vec<Item>,
    },
    Every {
        duration: Expr,
        body: Vec<Item>,
    },
    At {
        schedule: Expr,
        body: Vec<Item>,
    },
    Send {
        value: Expr,
        signer: Option<Expr>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExprKind {
    Identifier(String),
    Integer(i64),
    Decimal(String),
    Text(String),
    Bool(bool),
    None,
    Duration {
        value: u64,
        unit: String,
    },
    Percentage(u64),
    List(Vec<Expr>),
    Record(Vec<(Spanned<String>, Expr)>),
    Construct {
        name: Spanned<String>,
        fields: Vec<(Spanned<String>, Expr)>,
    },
    Call {
        callee: Box<Expr>,
        arguments: Vec<Expr>,
    },
    Member {
        value: Box<Expr>,
        name: Spanned<String>,
    },
    Index {
        value: Box<Expr>,
        index: Box<Expr>,
    },
    Unary {
        operator: String,
        value: Box<Expr>,
    },
    Binary {
        operator: String,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Assign {
        target: Box<Expr>,
        value: Box<Expr>,
    },
    Propagate(Box<Expr>),
    Select(SelectExpression),
    Sign {
        value: Box<Expr>,
        signer: Box<Expr>,
    },
    Publish {
        value: Box<Expr>,
        relays: Option<Box<Expr>>,
        signer: Option<Box<Expr>>,
    },
    Fetch {
        format: String,
        url: Box<Expr>,
    },
    Latest {
        event: TypeRef,
        arguments: Vec<Expr>,
        relays: Option<Box<Expr>>,
    },
    Match {
        value: Box<Expr>,
        arms: Vec<MatchArm>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectExpression {
    pub event: TypeRef,
    pub predicate: Option<Box<Expr>>,
    pub since: Option<Box<Expr>>,
    pub until: Option<Box<Expr>>,
    pub limit: Option<u64>,
    pub relays: Option<Box<Expr>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub guard: Option<Expr>,
    pub value: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatternKind {
    Wildcard,
    Binding(String),
    Literal(ExprKind),
    Variant {
        name: String,
        values: Vec<Pattern>,
    },
    Record {
        name: String,
        fields: Vec<(String, Option<Pattern>)>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeRef {
    pub name: String,
    pub arguments: Vec<TypeRef>,
    pub span: Span,
}
