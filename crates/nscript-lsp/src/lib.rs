//! A Language Server Protocol server for `NScript`.
//!
//! It adds no analysis of its own. Diagnostics, completions, hover and the
//! outline all come from [`nscript_lang`], which runs the same parse, module
//! resolution and semantic analysis as `nscript check`; the authority lens
//! comes from [`nscript_semantics::footprint`], the function Studio's
//! permission panel uses. A separate parser here would let the editor and the
//! CLI disagree, so there is none.
//!
//! The protocol layer is deliberately small and dependency-free (only
//! `serde_json`): full-document sync, no workspace features. Custom `-M`
//! module directories are not loaded; only the built-in standard library
//! resolves.

use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};

use nscript_lang::AnalyzedProgram;
use nscript_semantics::{footprint, infer};
use serde_json::{Value, json};

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const SERVER_NOT_INITIALIZED: i64 = -32002;

/// Converts a byte `offset` in `text` to an LSP `(line, UTF-16 character)`
/// position. An offset past the end, or inside a character, is clamped.
#[must_use]
pub fn offset_to_position(text: &str, offset: usize) -> (usize, usize) {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    let before = &text[..offset];
    let line = before.matches('\n').count();
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    let character = text[line_start..offset].encode_utf16().count();
    (line, character)
}

/// Converts an LSP `(line, UTF-16 character)` position to a byte offset in
/// `text`. A position past the end of its line is clamped to the line end; a
/// position past the last line is clamped to the end of the text.
#[must_use]
pub fn position_to_offset(text: &str, line: usize, character: usize) -> usize {
    let mut line_start = 0;
    for _ in 0..line {
        match text[line_start..].find('\n') {
            Some(index) => line_start += index + 1,
            None => return text.len(),
        }
    }
    let line_end = text[line_start..]
        .find('\n')
        .map_or(text.len(), |index| line_start + index);
    // A position inside a surrogate pair (which clients do not send) rounds
    // down to the start of that character, as `offset_to_position` does.
    let mut units = 0;
    for (index, ch) in text[line_start..line_end].char_indices() {
        let next = units + ch.len_utf16();
        if character < next {
            return line_start + index;
        }
        units = next;
    }
    line_end
}

fn range(text: &str, start: usize, end: usize) -> Value {
    let (start_line, start_character) = offset_to_position(text, start);
    let (end_line, end_character) = offset_to_position(text, end.max(start));
    json!({
        "start": {"line": start_line, "character": start_character},
        "end": {"line": end_line, "character": end_character},
    })
}

/// A diagnostic's range. A zero-width span (a missing token, say) is widened
/// to the next character so the editor has something to underline.
fn diagnostic_range(text: &str, start: usize, end: usize) -> Value {
    let end = if end > start {
        end
    } else {
        text[start.min(text.len())..]
            .chars()
            .next()
            .map_or(start, |ch| start + ch.len_utf8())
    };
    range(text, start, end)
}

fn completion_kind(kind: &str) -> u32 {
    match kind {
        "keyword" => 14,
        "module" => 9,
        "type" => 7,
        "event" => 23,
        "function" => 3,
        "operation" => 2,
        "tag" | "field" => 5,
        _ => 6,
    }
}

fn symbol_kind(kind: &str) -> u32 {
    match kind {
        "module" => 2,
        "event" => 24,
        "function" | "handler" => 12,
        _ => 13,
    }
}

/// Summarises a capability footprint on one line for an editor lens.
fn authority_title(groups: &[Value]) -> String {
    let parts = groups
        .iter()
        .filter_map(|group| {
            let name = group["name"].as_str()?;
            let items = group["items"]
                .as_array()?
                .iter()
                .filter_map(|item| {
                    let label = item["label"].as_str()?;
                    Some(match item["status"].as_str() {
                        Some("requested") => format!("{label} (not declared)"),
                        Some("forbidden") => format!("{label} (forbidden)"),
                        _ => label.to_owned(),
                    })
                })
                .collect::<Vec<_>>();
            (!items.is_empty()).then(|| format!("{name}: {}", items.join(", ")))
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "Authority: none".to_owned()
    } else {
        format!("Authority: {}", parts.join(" | "))
    }
}

/// The server's state: open documents and where the lifecycle has got to.
#[derive(Debug, Default)]
pub struct Server {
    documents: BTreeMap<String, String>,
    initialized: bool,
    shutdown_requested: bool,
    exit: Option<u8>,
}

impl Server {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The process exit code once the client has sent `exit`: 0 after a clean
    /// `shutdown`, 1 otherwise (LSP 3.17, "exit").
    #[must_use]
    pub fn exit_code(&self) -> Option<u8> {
        self.exit
    }

    /// Handles one decoded JSON-RPC message and returns the messages to send
    /// back, in order.
    pub fn handle(&mut self, message: &Value) -> Vec<Value> {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response to a request we never send, or a malformed message.
            return if message.get("id").is_some() && message.get("result").is_none() {
                vec![error_response(
                    message.get("id").cloned(),
                    INVALID_REQUEST,
                    "message has no method",
                )]
            } else {
                Vec::new()
            };
        };
        let id = message.get("id").cloned();
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let Some(id) = id else {
            return self.notification(method, &params);
        };
        if !self.initialized && method != "initialize" && method != "shutdown" {
            return vec![error_response(
                Some(id),
                SERVER_NOT_INITIALIZED,
                "the server is not initialized",
            )];
        }
        let outcome = self.request(method, &params);
        vec![match outcome {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, text)) => error_response(Some(id), code, &text),
        }]
    }

    fn request(&mut self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => {
                self.initialized = true;
                Ok(json!({
                    "capabilities": {
                        "positionEncoding": "utf-16",
                        "textDocumentSync": {"openClose": true, "change": 1},
                        "completionProvider": {"triggerCharacters": ["."]},
                        "hoverProvider": true,
                        "documentSymbolProvider": true,
                        "codeLensProvider": {"resolveProvider": false},
                    },
                    "serverInfo": {"name": "nscript-lsp", "version": env!("CARGO_PKG_VERSION")},
                }))
            }
            "shutdown" => {
                self.shutdown_requested = true;
                Ok(Value::Null)
            }
            "textDocument/completion" => {
                let (analysis, offset) = self.analysis_at(params)?;
                let items = nscript_lang::completions(&analysis, offset)
                    .into_iter()
                    .map(|completion| {
                        json!({
                            "label": completion.label,
                            "kind": completion_kind(completion.kind),
                            "detail": completion.detail,
                            "insertText": completion.insert,
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({"isIncomplete": false, "items": items}))
            }
            "textDocument/hover" => {
                let (analysis, offset) = self.analysis_at(params)?;
                Ok(
                    nscript_lang::hover(&analysis, offset).map_or(Value::Null, |hover| {
                        json!({"contents": {
                            "kind": "markdown",
                            "value": format!("**{}**\n\n{}", hover.label, hover.detail),
                        }})
                    }),
                )
            }
            "textDocument/documentSymbol" => {
                let (text, analysis) = self.analysis(params)?;
                let symbols = nscript_lang::symbols(&analysis)
                    .into_iter()
                    .map(|symbol| {
                        let span = range(&text, symbol.start, symbol.end);
                        json!({
                            "name": symbol.name,
                            "detail": symbol.detail,
                            "kind": symbol_kind(symbol.kind),
                            "range": span,
                            "selectionRange": span,
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(Value::Array(symbols))
            }
            "textDocument/codeLens" => {
                let (_, analysis) = self.analysis(params)?;
                let groups = authority_groups(&analysis);
                Ok(json!([{
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 0},
                    },
                    "command": {
                        "title": authority_title(&groups),
                        "command": "nscript.showAuthority",
                        "arguments": [groups],
                    },
                }]))
            }
            "nscript/authority" => {
                let (_, analysis) = self.analysis(params)?;
                Ok(json!({"groups": authority_groups(&analysis)}))
            }
            other => Err((METHOD_NOT_FOUND, format!("unsupported method `{other}`"))),
        }
    }

    fn notification(&mut self, method: &str, params: &Value) -> Vec<Value> {
        match method {
            "exit" => {
                self.exit = Some(u8::from(!self.shutdown_requested));
                Vec::new()
            }
            "textDocument/didOpen" => {
                let document = &params["textDocument"];
                let (Some(uri), Some(text)) = (document["uri"].as_str(), document["text"].as_str())
                else {
                    return Vec::new();
                };
                self.documents.insert(uri.to_owned(), text.to_owned());
                vec![self.diagnostics_for(uri)]
            }
            "textDocument/didChange" => {
                let Some(uri) = params["textDocument"]["uri"].as_str() else {
                    return Vec::new();
                };
                // Full-document sync: the last change carries the whole text.
                let Some(text) = params["contentChanges"]
                    .as_array()
                    .and_then(|changes| changes.last())
                    .and_then(|change| change["text"].as_str())
                else {
                    return Vec::new();
                };
                self.documents.insert(uri.to_owned(), text.to_owned());
                vec![self.diagnostics_for(uri)]
            }
            "textDocument/didClose" => {
                let Some(uri) = params["textDocument"]["uri"].as_str() else {
                    return Vec::new();
                };
                self.documents.remove(uri);
                // Clear what the editor was showing for a file it closed.
                vec![publish(uri, &[])]
            }
            _ => Vec::new(),
        }
    }

    fn diagnostics_for(&self, uri: &str) -> Value {
        let Some(text) = self.documents.get(uri) else {
            return publish(uri, &[]);
        };
        let analysis = nscript_lang::analyze(text, &[]);
        let diagnostics = analysis
            .diagnostics
            .iter()
            .map(|diagnostic| {
                json!({
                    "range": diagnostic_range(text, diagnostic.span.start, diagnostic.span.end),
                    "severity": 1,
                    "code": diagnostic.code,
                    "source": "nscript",
                    "message": diagnostic.message,
                })
            })
            .collect::<Vec<_>>();
        publish(uri, &diagnostics)
    }

    fn analysis(&self, params: &Value) -> Result<(String, AnalyzedProgram), (i64, String)> {
        let uri = params["textDocument"]["uri"]
            .as_str()
            .ok_or_else(|| (INVALID_PARAMS, "missing textDocument.uri".to_owned()))?;
        let text = self
            .documents
            .get(uri)
            .ok_or_else(|| (INVALID_PARAMS, format!("`{uri}` is not open")))?;
        let analysis = nscript_lang::analyze(text, &[]);
        Ok((text.clone(), analysis))
    }

    fn analysis_at(&self, params: &Value) -> Result<(AnalyzedProgram, usize), (i64, String)> {
        let (text, analysis) = self.analysis(params)?;
        let position = &params["position"];
        let (Some(line), Some(character)) =
            (position["line"].as_u64(), position["character"].as_u64())
        else {
            return Err((INVALID_PARAMS, "missing position".to_owned()));
        };
        let offset = position_to_offset(
            &text,
            usize::try_from(line).unwrap_or(usize::MAX),
            usize::try_from(character).unwrap_or(usize::MAX),
        );
        Ok((analysis, offset))
    }
}

/// The capability footprint as JSON groups. Computed even while the program
/// still has permission errors, so an undeclared permission shows up as
/// `requested` while you type, exactly as in Studio.
fn authority_groups(analysis: &AnalyzedProgram) -> Vec<Value> {
    let (inferred, typed) = infer(&analysis.program);
    let mut diagnostics = analysis.diagnostics.clone();
    diagnostics.extend(typed);
    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    let footprint = footprint(&analysis.program, &inferred, &analysis.graph, &diagnostics);
    serde_json::to_value(&footprint)
        .ok()
        .and_then(|value| value["groups"].as_array().cloned())
        .unwrap_or_default()
}

fn publish(uri: &str, diagnostics: &[Value]) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "textDocument/publishDiagnostics",
        "params": {"uri": uri, "diagnostics": diagnostics},
    })
}

fn error_response(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {"code": code, "message": message},
    })
}

/// Reads one `Content-Length`-framed message. `Ok(None)` is a clean end of
/// input between messages.
fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut length = None;
    let mut saw_header = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return if saw_header {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input ended inside a message header",
                ))
            } else {
                Ok(None)
            };
        }
        saw_header = true;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse::<usize>().ok();
        }
    }
    let length = length.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "message has no Content-Length")
    })?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_message<W: Write>(writer: &mut W, message: &Value) -> io::Result<()> {
    let body = message.to_string();
    write!(writer, "Content-Length: {}\r\n\r\n{body}", body.len())?;
    writer.flush()
}

/// Serves LSP over `reader`/`writer` until `exit` or end of input, returning
/// the process exit code. End of input without `exit` is treated as an
/// unclean exit (1), as the specification asks.
///
/// # Errors
///
/// Returns an error when the transport fails mid-message.
pub fn serve<R: BufRead, W: Write>(mut reader: R, mut writer: W) -> io::Result<u8> {
    let mut server = Server::new();
    while let Some(body) = read_message(&mut reader)? {
        let outgoing = match serde_json::from_slice::<Value>(&body) {
            Ok(message) => server.handle(&message),
            Err(error) => vec![error_response(None, PARSE_ERROR, &error.to_string())],
        };
        for message in &outgoing {
            write_message(&mut writer, message)?;
        }
        if let Some(code) = server.exit_code() {
            return Ok(code);
        }
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_count_utf16_units_not_bytes_or_chars() {
        // `😀` is 4 bytes, 1 char and 2 UTF-16 units.
        let text = "a😀b\nxyz";
        let b_offset = "a😀".len();
        assert_eq!(offset_to_position(text, b_offset), (0, 3));
        assert_eq!(position_to_offset(text, 0, 3), b_offset);
        assert_eq!(offset_to_position(text, text.len()), (1, 3));
        assert_eq!(position_to_offset(text, 1, 1), "a😀b\nx".len());
    }

    #[test]
    fn out_of_range_positions_clamp_instead_of_panicking() {
        let text = "ab\ncd";
        assert_eq!(position_to_offset(text, 0, 99), 2, "past the line end");
        assert_eq!(
            position_to_offset(text, 9, 0),
            text.len(),
            "past the last line"
        );
        assert_eq!(offset_to_position(text, 999), (1, 2), "past the end");
        // An offset inside a multi-byte character rounds down to its start.
        assert_eq!(offset_to_position("😀", 2), (0, 0));
    }

    #[test]
    fn a_position_inside_a_surrogate_pair_lands_on_the_character_start() {
        let text = "😀x";
        assert_eq!(position_to_offset(text, 0, 1), 0);
        assert_eq!(position_to_offset(text, 0, 2), "😀".len());
    }

    #[test]
    fn authority_titles_flag_undeclared_and_forbidden_items() {
        let groups = vec![
            json!({"name": "Publish", "items": [
                {"label": "Note", "status": "granted"},
                {"label": "Zap", "status": "requested"},
            ]}),
            json!({"name": "Other", "items": [{"label": "Shell", "status": "forbidden"}]}),
            json!({"name": "Empty", "items": []}),
        ];
        assert_eq!(
            authority_title(&groups),
            "Authority: Publish: Note, Zap (not declared) | Other: Shell (forbidden)"
        );
        assert_eq!(authority_title(&[]), "Authority: none");
    }
}
