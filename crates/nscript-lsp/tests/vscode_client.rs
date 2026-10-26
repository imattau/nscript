//! Runs the VS Code extension's Node tests (stubbed `vscode`, no editor).
//! Skipped with a message when Node is not installed; CI's runners have it.

use std::process::Command;

#[test]
fn the_vscode_extension_logic_passes_its_node_tests() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../editors/vscode");
    let output = match Command::new("node")
        .args(["--test", "test/extension.test.js"])
        .current_dir(&root)
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping: node is not installed");
            return;
        }
        Err(error) => panic!("could not run node: {error}"),
    };
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
