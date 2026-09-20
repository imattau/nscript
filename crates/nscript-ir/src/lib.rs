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

/// Emits a deterministic, valid WASM container for checked `NScript` IR.
///
/// The first backend intentionally carries the IR as custom sections and
/// declares capability imports; executable lowering is a later milestone.
///
/// # Panics
///
/// Panics only if the in-memory IR exceeds WASM's 32-bit section limits or
/// cannot be serialized, neither of which can occur for a checked program.
#[must_use]
pub fn emit_wasm(ir: &NostrIr) -> Vec<u8> {
    let mut module = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // One shared `() -> ()` function type for capability host calls and main.
    push_section(&mut module, 1, &[1, 0x60, 0, 0]);
    let operation_imports = ir
        .operations
        .iter()
        .enumerate()
        .map(|(index, operation)| format!("op:{index}:{}", operation_name(operation)))
        .collect::<Vec<_>>();
    {
        let mut imports = Vec::new();
        let import_count = ir.capabilities.len() + operation_imports.len();
        push_u32(
            &mut imports,
            u32::try_from(import_count).expect("import count fits WASM"),
        );
        for capability in &ir.capabilities {
            push_name(&mut imports, "nscript");
            push_name(
                &mut imports,
                &format!("{}:{}", capability.kind, capability.name),
            );
            imports.push(0); // function import
            imports.push(0); // type index
        }
        for operation in &operation_imports {
            push_name(&mut imports, "nscript");
            push_name(&mut imports, operation);
            imports.push(0);
            imports.push(0);
        }
        push_section(&mut module, 2, &imports);
    }
    // Define and export an executable entry point. Each declared capability is
    // called in stable order; host bindings provide the real typed arguments in
    // the next lowering stage.
    push_section(&mut module, 3, &[1, 0]);
    let mut export = Vec::new();
    push_u32(&mut export, 1);
    push_name(&mut export, "nscript_main");
    export.push(0);
    push_u32(
        &mut export,
        u32::try_from(ir.capabilities.len() + operation_imports.len())
            .expect("import count fits WASM"),
    );
    push_section(&mut module, 7, &export);
    let mut body = vec![0];
    for index in 0..ir.capabilities.len() {
        body.push(0x10);
        push_u32(
            &mut body,
            u32::try_from(index).expect("import index fits WASM"),
        );
    }
    for index in ir.capabilities.len()..(ir.capabilities.len() + operation_imports.len()) {
        body.push(0x10);
        push_u32(
            &mut body,
            u32::try_from(index).expect("import index fits WASM"),
        );
    }
    body.push(0x0b);
    let mut code = Vec::new();
    push_u32(&mut code, 1);
    push_u32(
        &mut code,
        u32::try_from(body.len()).expect("function body fits WASM"),
    );
    code.extend_from_slice(&body);
    push_section(&mut module, 10, &code);
    let ir_json = serde_json::to_vec(ir).expect("IR is serializable");
    push_custom_section(&mut module, "nscript.ir", &ir_json);
    let capabilities = ir
        .capabilities
        .iter()
        .map(|capability| format!("{}:{}", capability.kind, capability.name))
        .collect::<Vec<_>>();
    let capability_json = serde_json::to_vec(&capabilities).expect("capabilities are serializable");
    push_custom_section(&mut module, "nscript.capabilities", &capability_json);
    let dispatch_json = serde_json::to_vec(&ir.operations).expect("operations are serializable");
    push_custom_section(&mut module, "nscript.dispatch", &dispatch_json);
    module
}

fn operation_name(operation: &IrOperation) -> &'static str {
    match operation {
        IrOperation::CreateEvent { .. } => "create_event",
        IrOperation::SignEvent { .. } => "sign_event",
        IrOperation::PublishEvent { .. } => "publish_event",
    }
}

fn push_custom_section(module: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let mut section = Vec::new();
    push_name(&mut section, name);
    section.extend_from_slice(payload);
    push_section(module, 0, &section);
}

fn push_section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    push_u32(
        module,
        u32::try_from(payload.len()).expect("section payload fits WASM"),
    );
    module.extend_from_slice(payload);
}

fn push_name(output: &mut Vec<u8>, value: &str) {
    push_u32(
        output,
        u32::try_from(value.len()).expect("name length fits WASM"),
    );
    output.extend_from_slice(value.as_bytes());
}

fn push_u32(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{NostrIr, emit_wasm};

    #[test]
    fn wasm_artifact_is_valid_container_with_capability_metadata() {
        let ir = NostrIr {
            schema: "nscript-ir/0.1",
            profile: "standard",
            modules: Vec::new(),
            capabilities: vec![super::IrCapability {
                name: "public".to_owned(),
                kind: "relayset",
            }],
            permissions: vec!["publish Note".to_owned()],
            operations: Vec::new(),
        };
        let bytes = emit_wasm(&ir);
        assert_eq!(&bytes[..8], b"\0asm\x01\0\0\0");
        assert!(
            bytes
                .windows(b"nscript_main".len())
                .any(|window| window == b"nscript_main")
        );
        assert!(
            bytes
                .windows(b"nscript.capabilities".len())
                .any(|window| window == b"nscript.capabilities")
        );
        assert!(
            bytes
                .windows(b"relayset:public".len())
                .any(|window| window == b"relayset:public")
        );
        assert!(
            bytes
                .windows(b"nscript.dispatch".len())
                .any(|window| window == b"nscript.dispatch")
        );
    }
}
