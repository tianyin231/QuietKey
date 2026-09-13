import {test} from 'node:test';
import assert from 'node:assert/strict';
import {normalizeAccount,parseInput,totp,deriveKey,encryptVault,decryptVault} from '../dist/core.mjs';
function base32(text){let bits=0,value=0,result='';for(const b of new TextEncoder().encode(text)){value=(value<<8)|b;bits+=8;while(bits>=5){bits-=5;result+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value>>>bits)&31];}}if(bits)result+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value<<(5-bits))&31];return result;}
const vectors=[
 [59,'94287082','46119246','90693936'],
 [1111111109,'07081804','68084774','25091201'],
 [1111111111,'14050471','67062674','99943326'],
 [1234567890,'89005924','91819424','93441116'],
 [2000000000,'69279037','90698825','38618901'],
 [20000000000,'65353130','77737706','47863826'],
];
test('RFC 6238: all 18 reference vectors including SHA256/SHA512 and post-2038 time',async()=>{
 for(const [index,algorithm,length] of [[1,'SHA1',20],[2,'SHA256',32],[3,'SHA512',64]]){
   const a=normalizeAccount({secret:base32('1234567890'.repeat(7).slice(0,length)),algorithm,digits:8});
   for(const vector of vectors)assert.equal(await totp(a,vector[0]),vector[index]);
 }
});
test('URI, raw key, CSV quoted field and JSON imports preserve settings',()=>{
 const secret='JBSWY3DPEHPK3PXP';
 const a=parseInput(`otpauth://totp/GitHub:alex%40example.com?secret=${secret}&issuer=GitHub&algorithm=SHA256&digits=8&period=60`)[0];
 assert.equal(a.account,'alex@example.com');assert.equal(a.algorithm,'SHA256');assert.equal(a.digits,8);assert.equal(a.period,60);
 assert.equal(parseInput(`issuer,account,secret\n"Example, Inc",alex,${secret}`)[0].issuer,'Example, Inc');
 assert.equal(parseInput(JSON.stringify({accounts:[a]}))[0].period,60);
 assert.equal(parseInput('jbsw y3dp ehpk 3pxp')[0].secret,secret);
});
test('unsupported protocols and malformed inputs fail rather than silently change configuration',()=>{
 for(const input of ['otpauth://hotp/A?secret=JBSWY3DPEHPK3PXP','otpauth-migration://offline?data=test','INVALID1','[{"secret":"JBSWY3DPEHPK3PXP","digits":7}]','a,b,c,d'])assert.throws(()=>parseInput(input));
});
test('encrypted storage roundtrip, randomized ciphertext, wrong password and tampering rejection',async()=>{
 const a=normalizeAccount({issuer:'Test',secret:'JBSWY3DPEHPK3PXP'}),salt=crypto.getRandomValues(new Uint8Array(16)),password='disposable-test-password';
 const key=await deriveKey(password,salt);const one=await encryptVault([a],key,salt),two=await encryptVault([a],key,salt);
 assert.notEqual(one.data,two.data);assert.ok(!JSON.stringify(one).includes(a.secret));assert.ok(!JSON.stringify(one).includes('Test'));
 assert.equal((await decryptVault(one,password)).accounts[0].secret,a.secret);
 await assert.rejects(()=>decryptVault(one,'wrong'));
 const damaged={...one,data:(one.data[0]==='A'?'B':'A')+one.data.slice(1)};await assert.rejects(()=>decryptVault(damaged,password));
});
