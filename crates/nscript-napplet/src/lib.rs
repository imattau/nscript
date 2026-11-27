//! Capability mapping for the `NScript` "lens" napplet profile.
//!
//! The lens profile is deliberately small: one or more read-only `Note`
//! handlers, optional principal-scoped predicates, local presentation
//! decisions through the built-in `lens` module, and no publication, signing,
//! storage, schedules, inputs, keys, or third-party module operations.
//!
//! The profile is shared by the CLI requirement generator, the browser ABI,
//! and embedders that need to apply an enclosing applet's capability ceiling.

use nscript_semantics::{CheckedProgram, Effect};
use nscript_syntax::{
    Program,
    ast::{
        Expr, ExprKind, Item, MatchArm, Permission, SelectExpression, Statement, StatementKind,
        TypeRef,
    },
};

/// The NAP domains the lens profile requires.
pub const LENS_REQUIRED_DOMAINS: &[&str] = &["outbox"];

/// NAP domains the lens applet can use when the shell provides them.
pub const LENS_OPTIONAL_DOMAINS: &[&str] = &["identity", "storage"];

/// Backwards-compatible name for the original feed-filter profile.
pub const FEED_FILTER_DOMAINS: &[&str] = LENS_REQUIRED_DOMAINS;

/// The presentation operations the lens profile accepts.
pub const LENS_OPERATIONS: &[&str] = &["hide", "label", "pin", "flag"];

/// A single outbox query scope derived from one checked `on Note` handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerFilter {
    pub kinds: Vec<u16>,
    pub authors: Vec<String>,
    /// `(tag name, value)` pairs, lowered to NIP-01 `#name` filter keys.
    pub tags: Vec<(String, String)>,
    pub uses_principal: bool,
}

/// Validates that a checked program fits the lens adapter profile.
///
/// # Errors
///
/// Returns a diagnostic message when the program requests behavior outside
/// the read-only lens profile.
pub fn validate_lens_profile(program: &Program, checked: &CheckedProgram) -> Result<(), String> {
    let mut read_note = false;
    let mut relay_public = false;
    let mut permissions_supported = true;
    for item in &program.ast.items {
        if let Item::Permissions(block) = item {
            for permission in &block.value {
                match permission {
                    Permission::Read {
                        event,
                        relayset: Some(relayset),
                    } if is_note(event) && relayset.value == "public" => {
                        read_note = true;
                    }
                    Permission::Named {
                        operation,
                        argument: Some(argument),
                        scope: None,
                    } if operation.value == "relay" && argument.value == "public" => {
                        relay_public = true;
                    }
                    Permission::Named {
                        operation,
                        argument: None,
                        scope: None,
                    } if matches!(operation.value.as_str(), "log" | "view") => {}
                    _ => permissions_supported = false,
                }
            }
        }
    }

    let items_supported = program.ast.items.iter().all(|item| match item {
        Item::Use(import) => matches!(import.path.as_str(), "nip01" | "lens"),
        Item::RelaySet(_) | Item::Permissions(_) | Item::Function(_) => true,
        Item::Statement(statement) => matches!(&statement.value, StatementKind::On { .. }),
        _ => false,
    });
    let handlers_supported = !checked.handlers.is_empty()
        && checked.handlers.iter().all(|handler| {
            handler.event_type == "Note"
                && handler.author_input.is_none()
                && handler.tag_equals_inputs.is_empty()
                && handler.body_items <= 256
        });
    let effects_supported = checked
        .effects
        .iter()
        .all(|effect| matches!(effect, Effect::Relay | Effect::Log));
    let operations_supported = checked
        .operation_calls
        .iter()
        .all(|call| call.module == "lens" && LENS_OPERATIONS.contains(&call.operation.as_str()));
    let program_supported = items_supported
        && handlers_supported
        && permissions_supported
        && read_note
        && relay_public
        && effects_supported
        && operations_supported
        && checked.publications.is_empty()
        && checked.schedules.is_empty()
        && checked.keys.is_empty()
        && checked.inputs.is_empty()
        && program.publishes.is_empty();

    if program_supported {
        Ok(())
    } else {
        Err("lens scripts may only read Note events from `public`, use `nip01` and `lens`, and make local view decisions; publishing, signing, storage, schedules, inputs, keys, and other module operations are unsupported".to_owned())
    }
}

/// Backwards-compatible alias for the original feed-filter profile.
///
/// # Errors
///
/// Returns the lens profile diagnostic when the program is unsupported.
pub fn validate_feed_filter(program: &Program, checked: &CheckedProgram) -> Result<(), String> {
    validate_lens_profile(program, checked)
}

/// Whether any handler filter or handler/function body references `me`.
#[must_use]
pub fn principal_required(program: &Program, checked: &CheckedProgram) -> bool {
    checked.handlers.iter().any(|handler| {
        handler.author_is_principal
            || !handler.tag_equals_principal.is_empty()
            || handler.body.iter().any(item_uses_principal)
    }) || program
        .ast
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Function(function) => Some(function),
            _ => None,
        })
        .any(|function| function.body.iter().any(item_uses_principal))
}

/// Derives one NIP-01 outbox filter per checked handler.
///
/// Principal-scoped predicates are only resolved when `principal` is present;
/// callers should consult [`principal_required`] first and report a clear
/// "connect a signer" state themselves.
#[must_use]
pub fn handler_filters(checked: &CheckedProgram, principal: Option<&str>) -> Vec<HandlerFilter> {
    let mut filters = Vec::new();
    for handler in &checked.handlers {
        let kind = checked
            .events
            .get(&handler.event_type)
            .map_or(1, |event| event.kind);
        let mut filter = HandlerFilter {
            kinds: vec![kind],
            authors: Vec::new(),
            tags: Vec::new(),
            uses_principal: handler.author_is_principal || !handler.tag_equals_principal.is_empty(),
        };
        if handler.author_is_principal {
            if let Some(principal) = principal {
                filter.authors.push(principal.to_owned());
            }
        } else if let Some(author) = &handler.author {
            filter.authors.push(author.clone());
        }
        filter.tags.extend(handler.tag_equals.iter().cloned());
        if let Some(principal) = principal {
            filter.tags.extend(
                handler
                    .tag_equals_principal
                    .iter()
                    .map(|name| (name.clone(), principal.to_owned())),
            );
        }
        if !filters.contains(&filter) {
            filters.push(filter);
        }
    }
    filters
}

/// Serializes filters into the NIP-01 shape the shell's `outbox` domain takes.
///
/// The `limit` is applied by the applet, not by the source program.
#[must_use]
pub fn lower_filters(filters: &[HandlerFilter], limit: u64) -> Vec<FilterJson> {
    filters
        .iter()
        .map(|filter| {
            let mut tags = std::collections::BTreeMap::new();
            for (name, value) in &filter.tags {
                tags.entry(format!("#{name}"))
                    .or_insert_with(Vec::new)
                    .push(value.clone());
            }
            FilterJson {
                kinds: filter.kinds.clone(),
                authors: filter.authors.clone(),
                tags,
                limit,
            }
        })
        .collect()
}

/// A NIP-01 filter ready for JSON serialization by the ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterJson {
    pub kinds: Vec<u16>,
    pub authors: Vec<String>,
    pub tags: std::collections::BTreeMap<String, Vec<String>>,
    pub limit: u64,
}

/// Checks whether a program's required NAP domains fit an applet's ceiling.
///
/// # Errors
///
/// Returns the first required domain absent from the ceiling.
pub fn check_capability_ceiling<'a>(
    required: impl IntoIterator<Item = &'a str>,
    ceiling: &[String],
) -> Result<(), String> {
    for domain in required {
        if !ceiling.iter().any(|allowed| allowed == domain) {
            return Err(format!(
                "NScript program requires NAP domain `{domain}`, outside the applet capability ceiling"
            ));
        }
    }
    Ok(())
}

fn is_note(event: &TypeRef) -> bool {
    event.name == "Note" && event.arguments.is_empty()
}

fn item_uses_principal(item: &Item) -> bool {
    match item {
        Item::Use(_)
        | Item::Permissions(_)
        | Item::Runtime(_)
        | Item::Input(_)
        | Item::Store(_)
        | Item::Defaults { .. } => false,
        Item::Let(declaration) => expr_uses_principal(&declaration.value),
        Item::Function(function) => function.body.iter().any(item_uses_principal),
        Item::Event(event) => event
            .fields
            .iter()
            .filter_map(|field| field.default.as_ref())
            .any(expr_uses_principal),
        Item::Signer(declaration)
        | Item::Relay(declaration)
        | Item::RelaySet(declaration)
        | Item::Key(declaration) => expr_uses_principal(&declaration.value),
        Item::Stream { value, .. } => expr_uses_principal(value),
        Item::Statement(statement) => statement_uses_principal(statement),
    }
}

fn statement_uses_principal(statement: &Statement) -> bool {
    match &statement.value {
        StatementKind::Expression(value) | StatementKind::Return(Some(value)) => {
            expr_uses_principal(value)
        }
        StatementKind::Return(None) => false,
        StatementKind::For { value, body, .. } => {
            expr_uses_principal(value) || body.iter().any(item_uses_principal)
        }
        StatementKind::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_uses_principal(condition)
                || then_body.iter().any(item_uses_principal)
                || else_body.iter().any(item_uses_principal)
        }
        StatementKind::On {
            source,
            predicate,
            body,
        } => {
            expr_uses_principal(source)
                || predicate.as_ref().is_some_and(expr_uses_principal)
                || body.iter().any(item_uses_principal)
        }
        StatementKind::Once { key, body } => {
            expr_uses_principal(key) || body.iter().any(item_uses_principal)
        }
        StatementKind::Every { duration, body } => {
            expr_uses_principal(duration) || body.iter().any(item_uses_principal)
        }
        StatementKind::At { schedule, body } => {
            expr_uses_principal(schedule) || body.iter().any(item_uses_principal)
        }
        StatementKind::Send { value, signer } => {
            expr_uses_principal(value) || signer.as_ref().is_some_and(expr_uses_principal)
        }
    }
}

fn expr_uses_principal(expression: &Expr) -> bool {
    match &expression.value {
        ExprKind::Identifier(name) => name == "me",
        ExprKind::Integer(_)
        | ExprKind::Decimal(_)
        | ExprKind::Text(_)
        | ExprKind::Bool(_)
        | ExprKind::None
        | ExprKind::Duration { .. }
        | ExprKind::Percentage(_) => false,
        ExprKind::List(items) => items.iter().any(expr_uses_principal),
        ExprKind::Record(fields) | ExprKind::Construct { fields, .. } => {
            fields.iter().any(|(_, value)| expr_uses_principal(value))
        }
        ExprKind::Call { callee, arguments } => {
            expr_uses_principal(callee) || arguments.iter().any(expr_uses_principal)
        }
        ExprKind::Member { value, .. }
        | ExprKind::Unary { value, .. }
        | ExprKind::Propagate(value) => expr_uses_principal(value),
        ExprKind::Index { value, index } => {
            expr_uses_principal(value) || expr_uses_principal(index)
        }
        ExprKind::Binary { left, right, .. }
        | ExprKind::Assign {
            target: left,
            value: right,
        } => expr_uses_principal(left) || expr_uses_principal(right),
        ExprKind::Select(selection) => select_uses_principal(selection),
        ExprKind::Sign { value, signer } => {
            expr_uses_principal(value) || expr_uses_principal(signer)
        }
        ExprKind::Publish {
            value,
            relays,
            signer,
        } => {
            expr_uses_principal(value)
                || relays
                    .as_ref()
                    .is_some_and(|value| expr_uses_principal(value))
                || signer
                    .as_ref()
                    .is_some_and(|value| expr_uses_principal(value))
        }
        ExprKind::Fetch { url, .. } => expr_uses_principal(url),
        ExprKind::Latest {
            arguments, relays, ..
        } => {
            arguments.iter().any(expr_uses_principal)
                || relays
                    .as_ref()
                    .is_some_and(|value| expr_uses_principal(value))
        }
        ExprKind::Match { value, arms } => {
            expr_uses_principal(value) || arms.iter().any(match_arm_uses_principal)
        }
    }
}

fn select_uses_principal(selection: &SelectExpression) -> bool {
    selection
        .predicate
        .as_ref()
        .is_some_and(|value| expr_uses_principal(value))
        || selection
            .since
            .as_ref()
            .is_some_and(|value| expr_uses_principal(value))
        || selection
            .until
            .as_ref()
            .is_some_and(|value| expr_uses_principal(value))
        || selection
            .relays
            .as_ref()
            .is_some_and(|value| expr_uses_principal(value))
}

fn match_arm_uses_principal(arm: &MatchArm) -> bool {
    arm.guard.as_ref().is_some_and(expr_uses_principal) || expr_uses_principal(&arm.value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nscript_semantics::{bind_module_events, check};

    fn checked(source: &str) -> (Program, CheckedProgram) {
        let analysis = nscript_lang::analyze(source, &[]);
        assert!(
            analysis.diagnostics.is_empty(),
            "{:?}",
            analysis.diagnostics
        );
        let (mut checked, diagnostics) = check(&analysis.program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let mut checked = checked.take().expect("program checks");
        bind_module_events(&analysis.graph, &mut checked);
        (analysis.program, checked)
    }

    #[test]
    fn accepts_a_mentions_lens_and_derives_the_principal_filter() {
        let source = r#"use nip01
use lens
relayset public = configured
permissions {
    read Note from public
    relay public
    view
}
on Note where tags.p contains me {
    if event.content contains "spam" {
        lens.hide("promotion")
    }
}
"#;
        let (program, checked) = checked(source);
        assert!(validate_lens_profile(&program, &checked).is_ok());
        assert!(principal_required(&program, &checked));
        let filters = handler_filters(&checked, Some("abcdef"));
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].kinds, vec![1]);
        assert_eq!(filters[0].tags, vec![("p".to_owned(), "abcdef".to_owned())]);
        let lowered = lower_filters(&filters, 20);
        assert_eq!(lowered[0].limit, 20);
        assert_eq!(lowered[0].tags["#p"], vec!["abcdef"]);
    }

    #[test]
    fn accepts_a_following_lens_without_a_principal() {
        let source = r#"use nip01
use lens
relayset public = configured
permissions {
    read Note from public
    relay public
    view
}
on Note {
    lens.label("topic", "nostr")
}
"#;
        let (program, checked) = checked(source);
        assert!(validate_lens_profile(&program, &checked).is_ok());
        assert!(!principal_required(&program, &checked));
        let filters = handler_filters(&checked, None);
        assert_eq!(filters[0].tags.len(), 0);
        assert!(filters[0].authors.is_empty());
    }

    #[test]
    fn detects_me_used_only_in_a_handler_body() {
        let source = r#"use nip01
relayset public = configured
permissions {
    read Note from public
    relay public
    log
}
on Note {
    if event.author == text(me) {
        print("mine")
    }
}
"#;
        let (program, checked) = checked(source);
        assert!(principal_required(&program, &checked));
    }

    #[test]
    fn rejects_publication_and_third_party_operations() {
        let source = r#"use nip01
use nip46
signer account = nip46()
relayset public = configured
permissions {
    read Note from public
    publish Note to public
    sign Note with account
    relay public
}
on Note {
    publish Note { content: "no" } to public with account
}
"#;
        let (program, checked) = checked(source);
        assert!(validate_lens_profile(&program, &checked).is_err());
    }
}
