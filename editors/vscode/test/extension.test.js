// Tests the extension's own logic with `vscode` and `vscode-languageclient`
// stubbed, so it runs under plain Node. It does not start VS Code: that the
// extension loads and the server attaches in a real editor is verified by
// hand (see ../README.md).
const test = require('node:test');
const assert = require('node:assert');
const Module = require('node:module');

const calls = { clients: [], commands: {}, messages: [], started: 0, stopped: 0 };
let configured = {};
let startFails = false;

const stubs = {
    vscode: {
        workspace: { getConfiguration: () => ({ get: (key, fallback) => (key in configured ? configured[key] : fallback) }) },
        commands: { registerCommand: (name, handler) => { calls.commands[name] = handler; return { dispose() {} }; } },
        window: {
            showInformationMessage: (...args) => calls.messages.push(['info', ...args]),
            showErrorMessage: (...args) => calls.messages.push(['error', ...args]),
        },
    },
    'vscode-languageclient/node': {
        LanguageClient: class {
            constructor(...args) { calls.clients.push(args); }
            start() { calls.started += 1; return startFails ? Promise.reject(new Error('spawn ENOENT')) : Promise.resolve(); }
            stop() { calls.stopped += 1; return Promise.resolve(); }
        },
    },
};
const originalLoad = Module._load;
Module._load = function (request, ...rest) {
    return Object.prototype.hasOwnProperty.call(stubs, request) ? stubs[request] : originalLoad.call(this, request, ...rest);
};
const extension = require('../extension.js');

test('starts nscript-lsp for nscript files using the default path', async () => {
    const subscriptions = [];
    extension.activate({ subscriptions });
    const [id, , serverOptions, clientOptions] = calls.clients[0];
    assert.strictEqual(id, 'nscript');
    assert.deepStrictEqual(serverOptions, { command: 'nscript-lsp', args: [] });
    assert.deepStrictEqual(clientOptions.documentSelector, [{ scheme: 'file', language: 'nscript' }]);
    assert.strictEqual(calls.started, 1);
    assert.strictEqual(subscriptions.length, 1, 'the authority command is disposed with the extension');
    await extension.deactivate();
    assert.strictEqual(calls.stopped, 1);
});

test('honours nscript.server.path', () => {
    configured = { 'server.path': '/opt/nscript/bin/nscript-lsp' };
    extension.activate({ subscriptions: [] });
    assert.strictEqual(calls.clients.at(-1)[2].command, '/opt/nscript/bin/nscript-lsp');
    configured = {};
});

test('a server that will not start produces an actionable error, not a silent failure', async () => {
    startFails = true;
    extension.activate({ subscriptions: [] });
    await new Promise((resolve) => setImmediate(resolve));
    const error = calls.messages.find(([kind]) => kind === 'error');
    assert.ok(error, 'the user is told');
    assert.match(error[1], /Could not start nscript-lsp/);
    assert.match(error[1], /cargo build --release -p nscript-lsp/);
    startFails = false;
});

test('describes granted, undeclared and forbidden authority distinctly', () => {
    const text = extension.describeAuthority([
        { name: 'Publish', items: [{ label: 'Note', status: 'granted' }, { label: 'Zap', status: 'requested' }] },
        { name: 'Other', items: [{ label: 'Shell', status: 'forbidden' }] },
    ]);
    assert.match(text, /Publish: Note, Zap \(used, but not declared in permissions\)/);
    assert.match(text, /Other: Shell \(forbidden\)/);
    assert.strictEqual(extension.describeAuthority([]), 'This program requests no authority.');
    assert.strictEqual(extension.describeAuthority(undefined), 'This program requests no authority.');
});

test('the show-authority command displays the server groups', () => {
    extension.activate({ subscriptions: [] });
    calls.commands['nscript.showAuthority']([{ name: 'Publish', items: [{ label: 'Note', status: 'granted' }] }]);
    const shown = calls.messages.findLast(([kind]) => kind === 'info');
    assert.match(shown[1], /Publish: Note/);
    assert.deepStrictEqual(shown[2], { modal: true });
});
