//! Compile-time evaluation of module `require` lines.
//!
//! `spec/modules.md` says a requirement violation is a compile error when all
//! inputs are constant. This module evaluates that pure subset for a literal
//! constructor and reports a violation, resolving calls to other validators in
//! the same module graph.
//!
//! Anything it cannot evaluate — a computed field, an unsupported expression
//! (such as `matches`), or an ambiguous or missing validator — yields
//! [`Outcome::NotEvaluable`], never a guess. The declaration stays authoritative
//! for whatever the checker cannot evaluate.

use std::collections::BTreeMap;

use nscript_modules::{ResolvedModuleGraph, ValidatorDefinition};
use nscript_syntax::ast::{Expr, ExprKind};
use nscript_syntax::{TokenKind, lex};

/// The constant value a requirement expression can produce.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Literal {
    Text(String),
    Int(i64),
    Bool(bool),
}

/// The result of evaluating a constructor's requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// Every evaluable requirement holds.
    Satisfied,
    /// A requirement evaluated to false; the first one is returned.
    Violated(String),
    /// At least one requirement could not be evaluated, and none failed.
    NotEvaluable,
}

/// The literal value of a constructor field.
pub(crate) fn literal_field(expression: &Expr) -> Option<Literal> {
    match &expression.value {
        ExprKind::Text(value) => Some(Literal::Text(value.clone())),
        ExprKind::Integer(value) => Some(Literal::Int(*value)),
        ExprKind::Bool(value) => Some(Literal::Bool(*value)),
        _ => None,
    }
}

/// Evaluate `requirements` with `fields` bound as constants. `module` names the
/// declaration's module, which validator calls resolve in first.
pub(crate) fn evaluate(
    requirements: &[String],
    fields: &BTreeMap<String, Literal>,
    module: &str,
    graph: &ResolvedModuleGraph,
) -> Outcome {
    let evaluator = Evaluator { module, graph };
    let mut unevaluable = false;
    for requirement in requirements {
        match evaluator.requirement(requirement, fields, 0) {
            Some(true) => {}
            Some(false) => return Outcome::Violated(requirement.clone()),
            None => unevaluable = true,
        }
    }
    if unevaluable {
        Outcome::NotEvaluable
    } else {
        Outcome::Satisfied
    }
}

/// Identifiers named by a requirement, used to point the diagnostic at the
/// field the requirement mentions.
pub(crate) fn identifiers(requirement: &str) -> Vec<String> {
    lex(requirement)
        .into_iter()
        .filter_map(|token| match token.kind {
            TokenKind::Identifier(name) => Some(name),
            _ => None,
        })
        .collect()
}

const MAX_VALIDATOR_DEPTH: usize = 16;

struct Evaluator<'a> {
    module: &'a str,
    graph: &'a ResolvedModuleGraph,
}

impl Evaluator<'_> {
    fn requirement(
        &self,
        source: &str,
        fields: &BTreeMap<String, Literal>,
        depth: usize,
    ) -> Option<bool> {
        let tokens = lex(source)
            .into_iter()
            .filter(|token| token.kind != TokenKind::Newline)
            .collect::<Vec<_>>();
        let mut parser = Parser {
            tokens: &tokens,
            index: 0,
            evaluator: self,
            fields,
            depth,
        };
        let value = parser.expression()?;
        parser.at_end().then_some(())?;
        match value {
            Value::Bool(value) => Some(value),
            _ => None,
        }
    }

    /// Resolve a validator by name: the declaring module first, then a unique
    /// declaration elsewhere in the graph.
    fn validator(&self, name: &str) -> Option<&ValidatorDefinition> {
        if let Some(validator) = self.graph.modules.get(self.module).and_then(|module| {
            module
                .descriptor
                .validators
                .iter()
                .find(|validator| validator.name == name)
        }) {
            return Some(validator);
        }
        let mut found = None;
        for module in self.graph.modules.values() {
            for validator in &module.descriptor.validators {
                if validator.name != name {
                    continue;
                }
                if found.is_some() {
                    // Two modules declare the same name; refuse to guess.
                    return None;
                }
                found = Some(validator);
            }
        }
        found
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Text(String),
    Int(i64),
    Bool(bool),
}

struct Parser<'a> {
    tokens: &'a [nscript_syntax::Token],
    index: usize,
    evaluator: &'a Evaluator<'a>,
    fields: &'a BTreeMap<String, Literal>,
    depth: usize,
}

impl Parser<'_> {
    fn at_end(&self) -> bool {
        self.index >= self.tokens.len()
    }

    fn peek(&self) -> Option<&TokenKind> {
        self.tokens.get(self.index).map(|token| &token.kind)
    }

    fn advance(&mut self) -> Option<TokenKind> {
        let kind = self.tokens.get(self.index)?.kind.clone();
        self.index += 1;
        Some(kind)
    }

    fn symbol(&mut self, expected: char) -> bool {
        if matches!(self.peek(), Some(TokenKind::Symbol(value)) if *value == expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn word(&mut self, expected: &str) -> bool {
        if matches!(self.peek(), Some(TokenKind::Identifier(value)) if value == expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expression(&mut self) -> Option<Value> {
        self.or()
    }

    fn or(&mut self) -> Option<Value> {
        let mut left = self.and()?;
        while self.word("or") {
            let right = self.and()?;
            left = match (left, right) {
                (Value::Bool(left), Value::Bool(right)) => Value::Bool(left || right),
                _ => return None,
            };
        }
        Some(left)
    }

    fn and(&mut self) -> Option<Value> {
        let mut left = self.comparison()?;
        while self.word("and") {
            let right = self.comparison()?;
            left = match (left, right) {
                (Value::Bool(left), Value::Bool(right)) => Value::Bool(left && right),
                _ => return None,
            };
        }
        Some(left)
    }

    fn comparison(&mut self) -> Option<Value> {
        let left = self.unary()?;
        let operator = match self.peek() {
            Some(TokenKind::Symbol('=')) => {
                self.index += 1;
                self.symbol('=').then_some(Comparison::Equal)?
            }
            Some(TokenKind::Symbol('!')) => {
                self.index += 1;
                self.symbol('=').then_some(Comparison::NotEqual)?
            }
            Some(TokenKind::Symbol('>')) => {
                self.index += 1;
                if self.symbol('=') {
                    Comparison::GreaterOrEqual
                } else {
                    Comparison::Greater
                }
            }
            Some(TokenKind::Symbol('<')) => {
                self.index += 1;
                if self.symbol('=') {
                    Comparison::LessOrEqual
                } else {
                    Comparison::Less
                }
            }
            _ => return Some(left),
        };
        let right = self.unary()?;
        Some(Value::Bool(compare(operator, &left, &right)?))
    }

    fn unary(&mut self) -> Option<Value> {
        if self.word("not") {
            return match self.unary()? {
                Value::Bool(value) => Some(Value::Bool(!value)),
                _ => None,
            };
        }
        self.primary()
    }

    fn primary(&mut self) -> Option<Value> {
        match self.advance()? {
            TokenKind::String(value) => Some(Value::Text(value)),
            TokenKind::Number(value) => value.parse().ok().map(Value::Int),
            TokenKind::Symbol('(') => {
                let value = self.expression()?;
                self.symbol(')').then_some(value)
            }
            TokenKind::Identifier(name) if name == "true" => Some(Value::Bool(true)),
            TokenKind::Identifier(name) if name == "false" => Some(Value::Bool(false)),
            TokenKind::Identifier(name) => {
                if self.symbol('(') {
                    let arguments = self.arguments()?;
                    self.call(&name, &arguments)
                } else {
                    self.field(&name)
                }
            }
            _ => None,
        }
    }

    fn arguments(&mut self) -> Option<Vec<Value>> {
        let mut arguments = Vec::new();
        if self.symbol(')') {
            return Some(arguments);
        }
        loop {
            arguments.push(self.expression()?);
            if self.symbol(')') {
                return Some(arguments);
            }
            if !self.symbol(',') {
                return None;
            }
        }
    }

    fn field(&self, name: &str) -> Option<Value> {
        self.fields.get(name).map(|literal| match literal {
            Literal::Text(value) => Value::Text(value.clone()),
            Literal::Int(value) => Value::Int(*value),
            Literal::Bool(value) => Value::Bool(*value),
        })
    }

    fn call(&mut self, name: &str, arguments: &[Value]) -> Option<Value> {
        match (name, arguments) {
            ("length", [Value::Text(value)]) => {
                Some(Value::Int(i64::try_from(value.chars().count()).ok()?))
            }
            ("contains", [Value::Text(value), Value::Text(needle)]) => {
                Some(Value::Bool(value.contains(needle.as_str())))
            }
            // `matches` needs a regular-expression engine. Until then it stays
            // declarative rather than guess at a pattern.
            ("matches", _) => None,
            _ => {
                if self.depth >= MAX_VALIDATOR_DEPTH {
                    return None;
                }
                let validator = self.evaluator.validator(name)?;
                if validator.parameters.len() != arguments.len() {
                    return None;
                }
                let mut fields = BTreeMap::new();
                for (parameter, argument) in validator.parameters.iter().zip(arguments) {
                    let literal = match argument {
                        Value::Text(value) => Literal::Text(value.clone()),
                        Value::Int(value) => Literal::Int(*value),
                        Value::Bool(value) => Literal::Bool(*value),
                    };
                    fields.insert(parameter.name.clone(), literal);
                }
                let mut result = true;
                for requirement in &validator.requirements {
                    if !self
                        .evaluator
                        .requirement(requirement, &fields, self.depth + 1)?
                    {
                        result = false;
                    }
                }
                Some(Value::Bool(result))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Comparison {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

fn compare(operator: Comparison, left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Text(left), Value::Text(right)) => Some(match operator {
            Comparison::Equal => left == right,
            Comparison::NotEqual => left != right,
            _ => return None,
        }),
        (Value::Int(left), Value::Int(right)) => Some(match operator {
            Comparison::Equal => left == right,
            Comparison::NotEqual => left != right,
            Comparison::Greater => left > right,
            Comparison::GreaterOrEqual => left >= right,
            Comparison::Less => left < right,
            Comparison::LessOrEqual => left <= right,
        }),
        (Value::Bool(left), Value::Bool(right)) => Some(match operator {
            Comparison::Equal => left == right,
            Comparison::NotEqual => left != right,
            _ => return None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(values: &[(&str, &str)]) -> BTreeMap<String, Literal> {
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Literal::Text((*value).to_owned())))
            .collect()
    }

    fn outcome(requirements: &[&str], values: &BTreeMap<String, Literal>) -> Outcome {
        let graph = nscript_modules::ModuleRegistry::with_builtins()
            .resolve(&[])
            .expect("empty graph resolves");
        let requirements = requirements
            .iter()
            .map(|requirement| (*requirement).to_owned())
            .collect::<Vec<_>>();
        evaluate(&requirements, values, "test", &graph)
    }

    #[test]
    fn evaluates_comparisons_and_word_operators() {
        assert_eq!(
            outcome(
                &[r#"value=="draft" or value=="published""#],
                &fields(&[("value", "published")])
            ),
            Outcome::Satisfied
        );
        assert_eq!(
            outcome(
                &[r#"value=="draft" or value=="published""#],
                &fields(&[("value", "bogus")])
            ),
            Outcome::Violated(r#"value=="draft" or value=="published""#.to_owned())
        );
        assert_eq!(
            outcome(&["length(value) > 0"], &fields(&[("value", "x")])),
            Outcome::Satisfied
        );
        assert_eq!(
            outcome(&["length(value) > 0"], &fields(&[("value", "")])),
            Outcome::Violated("length(value) > 0".to_owned())
        );
    }

    #[test]
    fn unevaluable_inputs_are_not_guesses() {
        // A computed field is absent from the environment.
        assert_eq!(
            outcome(&[r#"value=="draft""#], &BTreeMap::new()),
            Outcome::NotEvaluable
        );
        // `matches` has no evaluator yet.
        assert_eq!(
            outcome(
                &[r#"matches(value, "^[0-9a-f]+$")"#],
                &fields(&[("value", "abc")])
            ),
            Outcome::NotEvaluable
        );
        // An unknown identifier (`zero_event_id`) or a truncated expression is
        // not a violation.
        assert_eq!(
            outcome(&["id != zero_event_id"], &fields(&[("id", "abc")])),
            Outcome::NotEvaluable
        );
        assert_eq!(
            outcome(&[r#"value =="#], &fields(&[("value", "abc")])),
            Outcome::NotEvaluable
        );
    }

    #[test]
    fn resolves_a_validator_in_the_declaring_module_first() {
        let registry = nscript_modules::ModuleRegistry::with_builtins();
        let graph = registry
            .resolve(&[
                nscript_modules::ModuleDependency {
                    name: "ncc02".to_owned(),
                    requirement: semver::VersionReq::STAR,
                },
                nscript_modules::ModuleDependency {
                    name: "ncc05".to_owned(),
                    requirement: semver::VersionReq::STAR,
                },
                nscript_modules::ModuleDependency {
                    name: "ncc13".to_owned(),
                    requirement: semver::VersionReq::STAR,
                },
            ])
            .expect("builtins resolve");
        // `present` is declared by several modules; the declaring module wins
        // even though it is not first in iteration order.
        assert_eq!(
            evaluate(
                &["present(d)".to_owned()],
                &fields(&[("d", "")]),
                "ncc13",
                &graph
            ),
            Outcome::Violated("present(d)".to_owned())
        );
    }

    #[test]
    fn resolves_a_validator_call_in_the_graph() {
        let source = r#"module words @ 0.1.0
language ">=0.1.0 <0.2.0"
validator identifier(value: Text) {
    require contains(value, "id-")
}
"#;
        let (descriptor, diagnostics) = nscript_modules::parse_module(source);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let mut registry = nscript_modules::ModuleRegistry::with_builtins();
        registry
            .register(
                descriptor.expect("descriptor"),
                nscript_modules::ModuleOrigin::File("words.nsm".into()),
            )
            .expect("register");
        let graph = registry
            .resolve(&[nscript_modules::ModuleDependency {
                name: "words".to_owned(),
                requirement: semver::VersionReq::STAR,
            }])
            .expect("resolve");
        assert_eq!(
            evaluate(
                &["identifier(d)".to_owned()],
                &fields(&[("d", "id-1")]),
                "words",
                &graph
            ),
            Outcome::Satisfied
        );
        assert_eq!(
            evaluate(
                &["identifier(d)".to_owned()],
                &fields(&[("d", "other")]),
                "words",
                &graph
            ),
            Outcome::Violated("identifier(d)".to_owned())
        );
    }
}
