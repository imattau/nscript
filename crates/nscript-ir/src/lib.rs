//! Deterministic, non-executable Nostr IR for inspected compiler output.

use nscript_modules::{ResolvedModuleGraph, hash_hex};
use nscript_semantics::CheckedProgram;
use nscript_syntax::{Program, RuntimeProfile};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NostrIr {
    pub schema: &'static str,
    pub profile: &'static str,
    pub modules: Vec<IrModule>,
    pub capabilities: Vec<IrCapability>,
    pub permissions: Vec<String>,
    pub operations: Vec<IrOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrModule {
    pub name: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrCapability {
    pub name: String,
    pub kind: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IrOperation {
    CreateEvent {
        result: String,
        event: String,
        kind: u16,
        content: Option<String>,
        created_at: &'static str,
    },
    SignEvent {
        result: String,
        event: String,
        signer: String,
    },
    PublishEvent {
        result: String,
        event: String,
        relayset: String,
    },
}

#[must_use]
pub fn lower(program: &Program, checked: &CheckedProgram, graph: &ResolvedModuleGraph) -> NostrIr {
    let modules = graph
        .modules
        .values()
        .map(|module| IrModule {
            name: module.descriptor.id.name.clone(),
            version: module.descriptor.id.version.to_string(),
            sha256: hash_hex(&module.descriptor.canonical_hash),
        })
        .collect();
    let mut capabilities = program
        .signers
        .iter()
        .map(|name| IrCapability {
            name: name.clone(),
            kind: "signer",
        })
        .chain(program.relaysets.iter().map(|name| IrCapability {
            name: name.clone(),
            kind: "relayset",
        }))
        .collect::<Vec<_>>();
    capabilities.sort_by(|left, right| left.name.cmp(&right.name));
    let mut operations = Vec::new();
    for (index, publication) in checked.publications.iter().enumerate() {
        let base = index * 3;
        let unsigned = format!("%{base}");
        let signed = format!("%{}", base + 1);
        let report = format!("%{}", base + 2);
        let kind = event_kind(graph, &publication.event).unwrap_or(1);
        operations.push(IrOperation::CreateEvent {
            result: unsigned.clone(),
            event: publication.event.clone(),
            kind,
            content: publication.content.clone(),
            created_at: "host",
        });
        operations.push(IrOperation::SignEvent {
            result: signed.clone(),
            event: unsigned,
            signer: publication.signer.clone(),
        });
        operations.push(IrOperation::PublishEvent {
            result: report,
            event: signed,
            relayset: publication.relayset.clone(),
        });
    }
    NostrIr {
        schema: "nscript-ir/0.1",
        profile: match program.profile {
            RuntimeProfile::Standard => "standard",
            RuntimeProfile::HardenedAgent => "hardened-agent",
        },
        modules,
        capabilities,
        permissions: permission_strings(program),
        operations,
    }
}

fn event_kind(graph: &ResolvedModuleGraph, name: &str) -> Option<u16> {
    graph.modules.values().find_map(|module| {
        module
            .descriptor
            .events
            .iter()
            .find(|event| event.name == name)
            .map(|event| event.kind)
    })
}

fn permission_strings(program: &Program) -> Vec<String> {
    let mut output = Vec::new();
    for item in &program.ast.items {
        if let nscript_syntax::ast::Item::Permissions(block) = item {
            for permission in &block.value {
                output.push(render_permission(permission));
            }
        }
    }
    output.sort();
    output
}

fn render_permission(permission: &nscript_syntax::ast::Permission) -> String {
    use nscript_syntax::ast::Permission;
    match permission {
        Permission::Read { event, relayset } => suffix(
            format!("read {}", event.name),
            "from",
            relayset.as_ref().map(|item| item.value.as_str()),
        ),
        Permission::Publish { event, relayset } => suffix(
            format!("publish {}", event.name),
            "to",
            relayset.as_ref().map(|item| item.value.as_str()),
        ),
        Permission::Sign { event, signer } => suffix(
            format!("sign {}", event.name),
            "with",
            signer.as_ref().map(|item| item.value.as_str()),
        ),
        Permission::Typed {
            operation,
            target,
            capability,
        } => suffix(
            format!("{} {}", operation.value, target.name),
            "with",
            capability.as_ref().map(|item| item.value.as_str()),
        ),
        Permission::Named {
            operation,
            argument,
        } => suffix(
            operation.value.clone(),
            "",
            argument.as_ref().map(|item| item.value.as_str()),
        ),
        Permission::Http(origin) => format!("http {}", origin.value),
    }
}

fn suffix(mut base: String, preposition: &str, value: Option<&str>) -> String {
    if let Some(value) = value {
        base.push(' ');
        if !preposition.is_empty() {
            base.push_str(preposition);
            base.push(' ');
        }
        base.push_str(value);
    }
    base
}
