// Copies the node icon (.svg) and codex metadata (.node.json) next to the
// compiled .node.js in dist/ — n8n expects them alongside the node at runtime.
import { cpSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const srcDir = join('nodes', 'DevTools');
const outDir = join('dist', 'nodes', 'DevTools');

mkdirSync(outDir, { recursive: true });
let copied = 0;
for (const file of readdirSync(srcDir)) {
  if (file.endsWith('.svg') || file.endsWith('.node.json')) {
    cpSync(join(srcDir, file), join(outDir, file));
    copied++;
  }
}
console.log(`Copied ${copied} node asset(s) to ${outDir}.`);
