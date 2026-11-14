#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');

const platform = process.platform;
const arch = process.arch;
const executable = platform === 'win32' ? '.exe' : '';
const target = {
  linux: { x64: 'linux-x64', arm64: 'linux-arm64' },
  darwin: { arm64: 'darwin-arm64' },
  win32: { x64: 'win-x64', arm64: 'win-arm64' }
}[platform]?.[arch] ?? null;

if (!target) {
  process.stderr.write('nscript: unsupported platform ' + platform + '/' + arch + '; supported: linux/x64, linux/arm64, darwin/arm64, win32/x64, win32/arm64\n');
  process.exit(1);
}

const cli = path.join(__dirname, target, 'nscript' + executable);
if (!existsSync(cli)) {
  process.stderr.write('nscript: bundled CLI is missing; reinstall the package\n');
  process.exit(1);
}

const child = spawn(cli, process.argv.slice(2), { stdio: 'inherit' });
child.on('error', error => {
  process.stderr.write('nscript: could not start CLI: ' + error.message + '\n');
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  process.exitCode = signal ? 1 : (code ?? 1);
});
