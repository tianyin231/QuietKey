import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import vm from 'node:vm';

const read=name=>readFile(new URL(`./dist/${name}`,import.meta.url),'utf8');
const [template,css,favicon,qr,core,app]=await Promise.all(['index.html','style.css','favicon.svg','vendor/jsQR.js','core.mjs','app.js'].map(read));
// Classic inline scripts work under file:// without module fetches or a local server.
// HTML parsing normalizes CRLF/CR before CSP hashes are checked.
// Hash exactly the LF-only script text the browser will execute.
const scripts=[qr,`(()=>{\n${core.replace(/^export /gm,'')}\n${app.replace(/^import .*;\r?\n/,'')}\n})();`].map(code=>code.replace(/\r\n?/g,'\n').replace(/<\/script/gi,'<\\/script'));
scripts.forEach(code=>new vm.Script(code));
const hashes=scripts.map(code=>`'sha256-${createHash('sha256').update(code).digest('base64')}'`).join(' ');
const html=template
 .replace(/<script\b[^>]*>[\s\S]*?<\/script>/g,'')
 .replace('script-src \'self\'',`script-src ${hashes}`)
 .replace('<link rel="stylesheet" href="./style.css">',()=>`<style>${css}</style>`)
 .replace('href="./favicon.svg"',`href="data:image/svg+xml,${encodeURIComponent(favicon)}"`)
 .replace('</body>',()=>scripts.map(code=>`<script>${code}</script>`).join('\n')+'\n</body>');
if (/<(?:script|link)\b[^>]*(?:src|href)="\.\//.test(html)) throw new Error('Standalone output still references external assets');
await writeFile(new URL('./栖钥-离线版.html',import.meta.url),html);
console.log(`Standalone HTML ready (${Math.round(Buffer.byteLength(html)/1024)} KB), no external assets.`);
