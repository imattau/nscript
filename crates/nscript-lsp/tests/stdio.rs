//! Drives the real `nscript-lsp` binary over stdio with `Content-Length`
//! framing, the way an editor does.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

use serde_json::{Value, json};

fn send(stdin: &mut impl Write, message: &Value) {
    let body = message.to_string();
    write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    stdin.flush().unwrap();
}

fn receive(stdout: &mut impl BufRead) -> Value {
    let mut length = 0;
    loop {
        let mut line = String::new();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "server closed early"
        );
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length: ") {
            length = value.parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    stdout.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[test]
fn a_full_editor_session_over_stdio() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nscript-lsp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}}),
    );
    let init = receive(&mut stdout);
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "nscript-lsp");
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // A UTF-8 body longer than its character count: the length header is bytes.
    let text = "use nip01\n// ünïcödé 😀\non Note { print(event.content) }\n";
    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": "file:///a.ns", "languageId": "nscript", "version": 1, "text": text}}
        }),
    );
    let published = receive(&mut stdout);
    assert_eq!(published["method"], "textDocument/publishDiagnostics");
    let codes: Vec<&str> = published["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_str().unwrap())
        .collect();
    assert!(!codes.is_empty(), "print needs the `log` permission");

    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
    );
    let shutdown = receive(&mut stdout);
    assert_eq!(shutdown["id"], 2);
    assert!(shutdown["result"].is_null());
    send(&mut stdin, &json!({"jsonrpc": "2.0", "method": "exit"}));

    let status = child.wait().unwrap();
    assert!(status.success(), "a clean shutdown then exit must exit 0");
}

#[test]
fn ending_input_without_exit_is_an_unclean_exit() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nscript-lsp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn garbage_json_gets_a_parse_error_not_a_crash() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nscript-lsp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    write!(stdin, "Content-Length: 8\r\n\r\n{{nope!!!").unwrap();
    stdin.flush().unwrap();
    let reply = receive(&mut stdout);
    assert_eq!(reply["error"]["code"], -32700);
    send(&mut stdin, &json!({"jsonrpc": "2.0", "method": "exit"}));
    assert_eq!(child.wait().unwrap().code(), Some(1));
}
