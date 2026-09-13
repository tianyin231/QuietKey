import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import vm from 'node:vm';

test('standalone scripts match CSP after browser HTML newline normalization',async()=>{
  const html=await readFile(new URL('../栖钥-离线版.html',import.meta.url),'utf8');
  const policy=html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length,2);
  for(const [,raw] of scripts){
    const parsed=raw.replace(/\r\n?/g,'\n');
    new vm.Script(parsed);
    const hash=createHash('sha256').update(parsed).digest('base64');
    assert.ok(policy.includes(`'sha256-${hash}'`),'Browser-normalized script must match CSP');
  }
  assert.ok(!/<(?:script|link)\b[^>]*(?:src|href)="\.\//.test(html));
});
