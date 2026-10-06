// Syntax-checks every backend source file (the backend has no linter configured).
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? (e.name === 'node_modules' ? [] : walk(path.join(dir, e.name))) : e.name.endsWith('.js') ? [path.join(dir, e.name)] : []);

const root = path.join(__dirname, '..');
const files = [...walk(path.join(root, 'src')), ...walk(path.join(root, 'scripts')), ...walk(path.join(root, 'tests'))];
let failed = 0;
for (const f of files) {
  try { execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' }); }
  catch (e) { failed++; console.error(`FAIL ${path.relative(root, f)}\n${e.stderr}`); }
}
console.log(`${files.length - failed}/${files.length} files OK`);
process.exit(failed ? 1 : 0);
