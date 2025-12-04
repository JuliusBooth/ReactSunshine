import { cpSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const distPath = path.join(root, 'dist');

if (existsSync(distPath)) {
  rmSync(distPath, { recursive: true, force: true });
}
mkdirSync(distPath);
cpSync(path.join(root, 'src'), distPath, { recursive: true });

console.log('Built Sunshine ESM package to dist');
