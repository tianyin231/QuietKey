// RFC 6238 TOTP. All secret processing stays on this device.
export function decodeBase32(value) {
  const s = String(value).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!s || !/^[A-Z2-7]+$/.test(s) || ![0,2,4,5,7].includes(s.length % 8)) throw new Error('密钥格式无效，请输入 Base32 密钥（A–Z、2–7）。');
  let bits = 0, buffer = 0; const bytes = [];
  for (const c of s) { buffer = (buffer << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c); bits += 5; if (bits >= 8) { bits -= 8; bytes.push((buffer >>> bits) & 255); } }
  if (bits && (buffer & ((1 << bits) - 1))) throw new Error('密钥末尾编码无效，请核对原始密钥。');
  if (bytes.length < 10) throw new Error('密钥过短，至少需要 16 个 Base32 字符。');
  return new Uint8Array(bytes);
}
export function normalizeAccount(input) {
  if (!input || typeof input !== 'object') throw new Error('账号数据格式不正确。');
  const secret = String(input.secret || '').toUpperCase().replace(/[\s-]/g,'').replace(/=+$/,'');
  decodeBase32(secret);
  const algorithm = String(input.algorithm || 'SHA1').toUpperCase().replace(/-/g,'');
  const digits = Number(input.digits ?? 6), period = Number(input.period ?? 30);
  if (!['SHA1','SHA256','SHA512'].includes(algorithm)) throw new Error('支持 SHA1、SHA256 和 SHA512。');
  if (![6,8].includes(digits)) throw new Error('验证码位数须为 6 或 8。');
  if (!Number.isInteger(period) || period < 15 || period > 120) throw new Error('更新周期须为 15–120 秒。');
  if (input.type && String(input.type).toLowerCase() !== 'totp') throw new Error('目前仅支持基于时间的 TOTP，不支持 HOTP。');
  return {id: crypto.randomUUID(), issuer: String(input.issuer || '未命名服务').trim().slice(0,80), account: String(input.account || input.name || '').trim().slice(0,150), secret, algorithm, digits, period, group: String(input.group || '个人').slice(0,40), favorite: Boolean(input.favorite)};
}
export function parseUri(text) {
  const url = new URL(text.trim());
  if (url.protocol !== 'otpauth:' || url.hostname !== 'totp') throw new Error('请输入 otpauth://totp/ 链接；迁移二维码和 HOTP 暂不支持。');
  const label = decodeURIComponent(url.pathname.slice(1));
  const colon = label.indexOf(':');
  return normalizeAccount({secret: url.searchParams.get('secret'), issuer: url.searchParams.get('issuer') || (colon >= 0 ? label.slice(0,colon) : label), account: colon >= 0 ? label.slice(colon+1) : label, algorithm: url.searchParams.get('algorithm') || 'SHA1', digits: url.searchParams.get('digits') || 6, period: url.searchParams.get('period') || 30});
}
function csvLine(line) {
  const fields = []; let current = '', quoted = false;
  for(let i=0;i<line.length;i++) { const c=line[i]; if(c==='"') { if(quoted && line[i+1]==='"') {current+='"';i++;} else quoted=!quoted; } else if(c===','&&!quoted) {fields.push(current.trim());current='';} else current+=c; }
  if(quoted) throw new Error('CSV 引号未闭合。'); fields.push(current.trim()); return fields;
}
export function parseInput(text) {
  const source = text.trim(); if (!source) throw new Error('请先输入要导入的内容。');
  if (source.length > 2_000_000) throw new Error('一次最多导入 2 MB 文本。');
  if (source.startsWith('[') || source.startsWith('{')) {
    const data = JSON.parse(source); const rows = Array.isArray(data) ? data : data.accounts;
    if (!Array.isArray(rows)) throw new Error('JSON 应为账号数组，或包含 accounts 数组。');
    if(rows.length>500) throw new Error('一次最多导入 500 个账号。');
    return rows.map(normalizeAccount);
  }
  const lines = source.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  if(lines.length>501) throw new Error('一次最多导入 500 个账号。');
  let header = null;
  if (lines[0].toLowerCase().includes('secret') && !lines[0].startsWith('otpauth:')) header = csvLine(lines.shift()).map(x=>x.toLowerCase());
  return lines.map((line,i) => {
    try {
      if(line.startsWith('otpauth:') || line.startsWith('otpauth-migration:')) return parseUri(line);
      if(line.includes(',')) {
        const values=csvLine(line);
        if(header) return normalizeAccount(Object.fromEntries(header.map((key,j)=>[key,values[j]])));
        if(values.length!==3) throw new Error('CSV 每行格式为：服务名称,账号,密钥。');
        return normalizeAccount({issuer:values[0],account:values[1],secret:values[2]});
      }
      return normalizeAccount({secret:line,issuer:lines.length===1?'新账号':`新账号 ${i+1}`});
    } catch(e) { throw new Error(`第 ${i+1+(header?1:0)} 行：${e.message}`); }
  });
}
export async function totp(account, seconds = Date.now()/1000) {
  const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(Math.floor(seconds/account.period)));
  const key = await crypto.subtle.importKey('raw',decodeBase32(account.secret),{name:'HMAC',hash:account.algorithm.replace('SHA','SHA-')},false,['sign']);
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC',key,bytes)); const offset=hash[hash.length-1]&15;
  const number = new DataView(hash.buffer).getUint32(offset)&0x7fffffff;
  return String(number % 10**account.digits).padStart(account.digits,'0');
}
const b64 = bytes => btoa(Array.from(bytes,x=>String.fromCharCode(x)).join(''));
const unb64 = text => Uint8Array.from(atob(text),x=>x.charCodeAt(0));
export async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export async function encryptVault(accounts,key,salt) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(JSON.stringify(accounts)));
  return {format:'quietkey',version:1,kdf:'PBKDF2-SHA256',iterations:600000,salt:b64(salt),iv:b64(iv),data:b64(new Uint8Array(data))};
}
export async function decryptVault(envelope,password) {
  if(envelope?.format!=='quietkey'||envelope.version!==1||envelope.iterations!==600000||envelope.kdf!=='PBKDF2-SHA256') throw new Error('不是受支持的栖钥加密备份。');
  const salt=unb64(envelope.salt),iv=unb64(envelope.iv);
  if(salt.length!==16||iv.length!==12) throw new Error('加密文件已损坏。');
  const key=await deriveKey(password,salt);
  let clear;
  try {clear=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,unb64(envelope.data));} catch {throw new Error('密码不正确，或备份文件已损坏。');}
  const rows=JSON.parse(new TextDecoder().decode(clear));
  if(!Array.isArray(rows)||rows.length>5000) throw new Error('备份账号数据不正确。');
  return {accounts:rows.map(normalizeAccount),key,salt};
}
