import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('./dist/',import.meta.url));
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
const port=Number(process.env.PORT||8765);
http.createServer(async(req,res)=>{
  try {
    const url=new URL(req.url,'http://localhost');
    const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));
    if(!file.startsWith(root)||!['GET','HEAD'].includes(req.method)){res.writeHead(403);return res.end();}
    const body=await readFile(file);
    res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store','X-Frame-Options':'DENY'});
    res.end(req.method==='HEAD'?undefined:body);
  }catch{res.writeHead(404);res.end('Not found');}
}).listen(port,'127.0.0.1',()=>console.log(`QuietKey: http://127.0.0.1:${port}`));
