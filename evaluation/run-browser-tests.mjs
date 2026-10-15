import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const directory = fileURLToPath(new URL('../extension/test/', import.meta.url));
const files = readdirSync(directory).filter(name => name.endsWith('.test.js')).sort();
if (!files.length) throw new Error('No browser tests found');
const result = spawnSync(process.execPath, ['--test', ...files.map(name => directory + name)], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
