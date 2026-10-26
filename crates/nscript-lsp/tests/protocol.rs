use nscript_lsp::{Server, position_to_offset};
use serde_json::{Value, json};

const URI: &str = "file:///work/bot.ns";

fn request(server: &mut Server, id: u64, method: &str, params: &Value) -> Value {
    let mut replies =
        server.handle(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
    assert_eq!(
        replies.len(),
        1,
        "{method} should produce exactly one reply"
    );
    replies.remove(0)
}

fn notify(server: &mut Server, method: &str, params: &Value) -> Vec<Value> {
    server.handle(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
}

fn started() -> Server {
    let mut server = Server::new();
    request(&mut server, 1, "initialize", &json!({"capabilities": {}}));
    notify(&mut server, "initialized", &json!({}));
    server
}

fn open(server: &mut Server, text: &str) -> Vec<Value> {
    notify(
        server,
        "textDocument/didOpen",
        &json!({"textDocument": {"uri": URI, "languageId": "nscript", "version": 1, "text": text}}),
    )
}

fn diagnostics(messages: &[Value]) -> Vec<Value> {
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["method"], "textDocument/publishDiagnostics");
    assert_eq!(messages[0]["params"]["uri"], URI);
    messages[0]["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .clone()
}

const VALID: &str = "use nip01\nuse nip46\n\nsigner account = nip46()\nrelayset public = configured\n\npermissions {\n    publish Note to public\n    sign Note with account\n    relay public\n}\n\npublish Note {\n    content: \"hi\"\n} to public with account\n";

#[test]
fn requests_before_initialize_are_refused() {
    let mut server = Server::new();
    let reply = request(&mut server, 1, "textDocument/hover", &json!({}));
    assert_eq!(reply["error"]["code"], -32002);
}

#[test]
fn initialize_advertises_the_supported_features() {
    let mut server = Server::new();
    let reply = request(&mut server, 1, "initialize", &json!({"capabilities": {}}));
    let capabilities = &reply["result"]["capabilities"];
    assert_eq!(capabilities["textDocumentSync"]["change"], 1, "full sync");
    assert_eq!(capabilities["hoverProvider"], true);
    assert_eq!(capabilities["documentSymbolProvider"], true);
    assert_eq!(capabilities["positionEncoding"], "utf-16");
    assert_eq!(reply["result"]["serverInfo"]["name"], "nscript-lsp");
}

#[test]
fn a_valid_program_has_no_diagnostics_and_a_broken_one_has_the_checkers_code() {
    let mut server = started();
    assert!(diagnostics(&open(&mut server, VALID)).is_empty());

    // The wrong-typed argument from conformance/invalid: the checker's own E1001.
    let broken = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/invalid/ncc03-window-wrong-type.ns"),
    )
    .unwrap();
    let found = diagnostics(&notify(
        &mut server,
        "textDocument/didChange",
        &json!({"textDocument": {"uri": URI, "version": 2}, "contentChanges": [{"text": broken}]}),
    ));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["code"], "E1001");
    assert_eq!(found[0]["source"], "nscript");
    assert_eq!(found[0]["severity"], 1);
    assert_eq!(
        found[0]["range"]["start"]["line"], 12,
        "line 13, zero-based"
    );

    // Fixing it clears the squiggle.
    assert!(
        diagnostics(&notify(
            &mut server,
            "textDocument/didChange",
            &json!({"textDocument": {"uri": URI, "version": 3}, "contentChanges": [{"text": VALID}]}),
        ))
        .is_empty()
    );
}

#[test]
fn closing_a_document_clears_its_diagnostics() {
    let mut server = started();
    open(&mut server, "this is not a program");
    let cleared = diagnostics(&notify(
        &mut server,
        "textDocument/didClose",
        &json!({"textDocument": {"uri": URI}}),
    ));
    assert!(cleared.is_empty());
    let reply = request(
        &mut server,
        2,
        "textDocument/documentSymbol",
        &json!({"textDocument": {"uri": URI}}),
    );
    assert_eq!(
        reply["error"]["code"], -32602,
        "a closed document is not served"
    );
}

#[test]
fn completion_after_a_module_dot_offers_that_modules_exports() {
    let mut server = started();
    let text = "use ncc03\n\non Note {\n    ncc03.\n}\n";
    open(&mut server, text);
    let reply = request(
        &mut server,
        2,
        "textDocument/completion",
        &json!({"textDocument": {"uri": URI}, "position": {"line": 3, "character": 10}}),
    );
    let labels: Vec<&str> = reply["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["label"].as_str().unwrap())
        .collect();
    assert!(labels.contains(&"vote_is_valid"), "{labels:?}");
    assert!(labels.contains(&"window_is_open"), "{labels:?}");
}

#[test]
fn hover_explains_a_module_function() {
    let mut server = started();
    let text = "use ncc03\n\non Note {\n    print(text(ncc03.vote_supersedes(1, 2)))\n}\n";
    open(&mut server, text);
    let line = text.lines().nth(3).unwrap();
    let character = line.find("vote_supersedes").unwrap() + 3;
    let reply = request(
        &mut server,
        2,
        "textDocument/hover",
        &json!({"textDocument": {"uri": URI}, "position": {"line": 3, "character": character}}),
    );
    let value = reply["result"]["contents"]["value"]
        .as_str()
        .expect("hover has text");
    assert!(value.contains("vote_supersedes"), "{value}");
    assert_eq!(reply["result"]["contents"]["kind"], "markdown");
    // Hovering whitespace explains nothing.
    let blank = request(
        &mut server,
        3,
        "textDocument/hover",
        &json!({"textDocument": {"uri": URI}, "position": {"line": 2, "character": 0}}),
    );
    assert!(blank["result"].is_null());
}

#[test]
fn document_symbols_outline_the_programs_declarations() {
    let mut server = started();
    open(&mut server, VALID);
    let reply = request(
        &mut server,
        2,
        "textDocument/documentSymbol",
        &json!({"textDocument": {"uri": URI}}),
    );
    let names: Vec<&str> = reply["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| symbol["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"account"), "{names:?}");
    assert!(names.contains(&"public"), "{names:?}");
    for symbol in reply["result"].as_array().unwrap() {
        assert_eq!(symbol["range"], symbol["selectionRange"]);
    }
}

#[test]
fn the_authority_lens_shows_what_the_program_may_do_and_what_it_forgot_to_declare() {
    let mut server = started();
    open(&mut server, VALID);
    let reply = request(
        &mut server,
        2,
        "textDocument/codeLens",
        &json!({"textDocument": {"uri": URI}}),
    );
    let title = reply["result"][0]["command"]["title"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(title.starts_with("Authority: "), "{title}");
    assert!(title.contains("Note"), "{title}");
    assert!(!title.contains("not declared"), "{title}");

    // Drop the publish permission: the capability is still used, so it
    // appears as requested-but-undeclared rather than disappearing.
    let undeclared = VALID.replace("    publish Note to public\n", "");
    notify(
        &mut server,
        "textDocument/didChange",
        &json!({"textDocument": {"uri": URI, "version": 2}, "contentChanges": [{"text": undeclared}]}),
    );
    let reply = request(
        &mut server,
        3,
        "textDocument/codeLens",
        &json!({"textDocument": {"uri": URI}}),
    );
    let title = reply["result"][0]["command"]["title"].as_str().unwrap();
    assert!(title.contains("(not declared)"), "{title}");

    let custom = request(
        &mut server,
        4,
        "nscript/authority",
        &json!({"textDocument": {"uri": URI}}),
    );
    assert!(custom["result"]["groups"].as_array().is_some());
}

#[test]
fn unknown_requests_fail_cleanly_and_unknown_notifications_are_ignored() {
    let mut server = started();
    let reply = request(&mut server, 2, "textDocument/rename", &json!({}));
    assert_eq!(reply["error"]["code"], -32601);
    assert!(notify(&mut server, "$/setTrace", &json!({"value": "off"})).is_empty());
}

#[test]
fn missing_params_are_invalid_params_not_a_crash() {
    let mut server = started();
    open(&mut server, VALID);
    let reply = request(
        &mut server,
        2,
        "textDocument/hover",
        &json!({"textDocument": {"uri": URI}}),
    );
    assert_eq!(reply["error"]["code"], -32602);
}

#[test]
fn exit_code_is_zero_after_shutdown_and_one_without() {
    let mut clean = started();
    request(&mut clean, 2, "shutdown", &Value::Null);
    notify(&mut clean, "exit", &Value::Null);
    assert_eq!(clean.exit_code(), Some(0));

    let mut abrupt = started();
    notify(&mut abrupt, "exit", &Value::Null);
    assert_eq!(abrupt.exit_code(), Some(1));
}

#[test]
fn completion_positions_use_utf16_units() {
    // The emoji before the cursor is two UTF-16 units; the server must map the
    // client's column to the right byte, not treat it as one or four.
    let text = "use ncc03\n// 😀\non Note {\n    ncc03.\n}\n";
    let offset = position_to_offset(text, 3, 10);
    assert!(text[..offset].ends_with("ncc03."), "{:?}", &text[..offset]);
}

/// The VS Code grammar highlights the same statement keywords the language
/// offers as completions; adding a keyword to `nscript-lang` without the
/// grammar would leave it unhighlighted.
#[test]
fn the_vscode_grammar_highlights_every_statement_keyword() {
    let grammar: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../editors/vscode/syntaxes/nscript.tmLanguage.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let keywords = grammar["repository"]["keyword"]["patterns"][0]["match"]
        .as_str()
        .unwrap();
    for keyword in nscript_lang::STATEMENT_KEYWORDS {
        assert!(
            keywords.contains(&format!("|{keyword}|"))
                || keywords.contains(&format!("(?:{keyword}|"))
                || keywords.contains(&format!("|{keyword})")),
            "the grammar does not highlight `{keyword}`"
        );
    }
    assert_eq!(grammar["scopeName"], "source.nscript");
}

#[test]
fn the_vscode_manifest_points_at_files_that_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../editors/vscode");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("package.json")).unwrap()).unwrap();
    for path in [
        manifest["main"].as_str().unwrap(),
        manifest["contributes"]["grammars"][0]["path"]
            .as_str()
            .unwrap(),
        manifest["contributes"]["languages"][0]["configuration"]
            .as_str()
            .unwrap(),
    ] {
        assert!(root.join(path).is_file(), "{path} is declared but missing");
    }
    assert_eq!(manifest["contributes"]["languages"][0]["id"], "nscript");
    assert_eq!(
        manifest["contributes"]["configuration"]["properties"]["nscript.server.path"]["default"],
        "nscript-lsp"
    );
}
