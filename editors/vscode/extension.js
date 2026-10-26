// Thin VS Code client for nscript-lsp. All analysis happens in the server,
// which runs the same front end as `nscript check`; nothing is parsed here.
const vscode = require('vscode');
const { LanguageClient } = require('vscode-languageclient/node');

let client;

// Renders the server's capability groups, e.g. [{name, items: [{label, status}]}].
function describeAuthority(groups) {
    if (!Array.isArray(groups) || groups.length === 0) {
        return 'This program requests no authority.';
    }
    return groups
        .map((group) => {
            const items = (group.items || []).map((item) => {
                if (item.status === 'requested') return `${item.label} (used, but not declared in permissions)`;
                if (item.status === 'forbidden') return `${item.label} (forbidden)`;
                return item.label;
            });
            return `${group.name}: ${items.join(', ')}`;
        })
        .join('\n');
}

function activate(context) {
    const command = vscode.workspace.getConfiguration('nscript').get('server.path', 'nscript-lsp');
    client = new LanguageClient(
        'nscript',
        'NScript',
        { command, args: [] },
        { documentSelector: [{ scheme: 'file', language: 'nscript' }] },
    );
    context.subscriptions.push(
        vscode.commands.registerCommand('nscript.showAuthority', (groups) => {
            vscode.window.showInformationMessage(describeAuthority(groups), { modal: true });
        }),
    );
    client.start().catch((error) => {
        vscode.window.showErrorMessage(
            `Could not start ${command}: ${error.message}. Build it with \`cargo build --release -p nscript-lsp\` or set nscript.server.path.`,
        );
    });
}

function deactivate() {
    return client ? client.stop() : undefined;
}

module.exports = { activate, deactivate, describeAuthority };
