#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');

const platform = process.platform;
const arch = process.arch;
const target = platform === 'linux' && arch === 'x64'
  ? 'linux-x64'
  : platform === 'darwin' && arch === 'arm64'
    ? 'darwin-arm64'
    : null;

if (!target) {
  process.stderr.write('nscript-mcp: unsupported platform ' + platform + '/' + arch + '; supported: linux/x64, darwin/arm64\n');
  process.exit(1);
}

const binDir = path.join(__dirname, target);
const cli = path.join(binDir, 'nscript');
const server = path.join(binDir, 'nscript-mcp');
if (!existsSync(cli) || !existsSync(server)) {
  process.stderr.write('nscript-mcp: bundled binaries are missing; reinstall the package\n');
  process.exit(1);
}

const child = spawn(server, process.argv.slice(2), {
  stdio: 'inherit',
  env: { ...process.env, NSCRIPT_CLI_PATH: cli }
});
child.on('error', error => {
  process.stderr.write('nscript-mcp: could not start server: ' + error.message + '\n');
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  process.exitCode = signal ? 1 : (code ?? 1);
});
