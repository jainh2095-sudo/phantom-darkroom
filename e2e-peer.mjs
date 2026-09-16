// TEMPORARY E2E test harness — byte-exact replica of Securechat.jsx crypto.
// Connects to the standalone relay as a second participant and proves:
//   1. peer→app:  encrypted MSG sent from here decrypts in the browser app
//   2. app→peer:  the app's encrypted CONFIRM decrypts here
// Run: node e2e-peer.mjs <room> <key>
import WebSocket from 'ws';
import { webcrypto, pbkdf2Sync } from 'node:crypto';

const crypto = webcrypto;
const ENC = new TextEncoder(), DEC = new TextDecoder();
const b64e = b => { const bytes = b instanceof Uint8Array ? b : new Uint8Array(b); let o=''; for (let i=0;i<bytes.length;i+=4096) o+=String.fromCharCode(...bytes.subarray(i,i+4096)); return btoa(o); };
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const concat = (...a) => { const o=new Uint8Array(a.reduce((s,x)=>s+x.length,0));let off=0;for(const x of a){o.set(x,off);off+=x.length;}return o; };
const wipe = a => a.fill(0);

async function sha256(data){ return new Uint8Array(await crypto.subtle.digest('SHA-256', data instanceof Uint8Array?data:ENC.encode(data))); }
async function hkdfBits(km,salt,info,bits=512){ const b=await crypto.subtle.importKey('raw',km,'HKDF',false,['deriveBits']); return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-512',salt:ENC.encode(salt),info:ENC.encode(info)},b,bits)); }
async function hkdfAES(km,salt,info){ const b=await crypto.subtle.importKey('raw',km,'HKDF',false,['deriveKey']); return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-512',salt:ENC.encode(salt),info:ENC.encode(info)},b,{name:'AES-GCM',length:256},false,['encrypt','decrypt']); }
async function hkdfHMAC(km,salt,info){ const b=await crypto.subtle.importKey('raw',km,'HKDF',false,['deriveKey']); return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-512',salt:ENC.encode(salt),info:ENC.encode(info)},b,{name:'HMAC',hash:'SHA-512',length:512},false,['sign','verify']); }
const hmacSign = async (data,key)=>b64e(await crypto.subtle.sign('HMAC',key,data instanceof Uint8Array?data:ENC.encode(data)));

const genKeypair = () => crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
const exportPub = async kp => b64e(await crypto.subtle.exportKey('raw',kp.publicKey));
const importPub = b64 => crypto.subtle.importKey('raw',b64d(b64),{name:'ECDH',namedCurve:'P-256'},false,[]);
const ecdhBits = async (priv,pub)=>new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:pub},priv,256));

const ROOM = (process.argv[2] || 'CRYPTOTEST').trim();
const RKEY = (process.argv[3] || 'Xq7#vT2$mK9pLw4zRn8sJf3Yb6hGd1cA').trim();
const MY = 'RELAY-PROBE';

// roomBits — replicate stretchKey: PBKDF2-SHA512, 2×100k, salt "phantom-v7:<room>:p1" then ":p2"
const safeKey = RKEY.slice(0,64), safeRoom = ROOM.slice(0,32);
const ROOMBITS = new Uint8Array(pbkdf2Sync(
  pbkdf2Sync(Buffer.from(safeKey,'utf8'), Buffer.from(`phantom-v7:${safeRoom}:p1`,'utf8'), 100000, 64, 'sha512'),
  Buffer.from(`phantom-v7:${safeRoom}:p2`,'utf8'), 100000, 64, 'sha512'));
const channel = Array.from(await sha256(ENC.encode('phantom-room-v7:'+ROOM))).map(b=>b.toString(16).padStart(2,'0')).join('').slice(0,16);

class SignalIdentity {
  constructor(){this.IK=null;this.SPK=null;this.OPK=null;this.SPKsig=null;}
  async generate(){
    this.IK=await genKeypair();this.SPK=await genKeypair();this.OPK=await genKeypair();
    const ikBits=await ecdhBits(this.IK.privateKey,await importPub(await exportPub(this.IK)));
    const hmacKey=await hkdfHMAC(ikBits,'phantom-ik-sign','spk-signature');
    this.SPKsig=await crypto.subtle.sign('HMAC',hmacKey,b64d(await exportPub(this.SPK)));
    return this;
  }
  async exportBundle(){return{ik:await exportPub(this.IK),spk:await exportPub(this.SPK),spkSig:b64e(this.SPKsig),opk:await exportPub(this.OPK)};}
}
const derivePQComponent=(rb,ctx)=>hkdfBits(rb,'phantom-pq-v7',ctx+':pq-hardening',512);
async function x3dhAgree(myId,theirBundle,roomBits){
  const myIk=await exportPub(myId.IK),theirIk=theirBundle.ik;
  const forward=myIk<=theirIk;
  const theirIK=await importPub(theirIk),theirSPK=await importPub(theirBundle.spk),theirOPK=await importPub(theirBundle.opk);
  const [dh1,dh2,dh3,dh4]=forward
    ? await Promise.all([ecdhBits(myId.IK.privateKey,theirSPK),ecdhBits(myId.SPK.privateKey,theirIK),ecdhBits(myId.IK.privateKey,theirOPK),ecdhBits(myId.OPK.privateKey,theirIK)])
    : await Promise.all([ecdhBits(myId.SPK.privateKey,theirIK),ecdhBits(myId.IK.privateKey,theirSPK),ecdhBits(myId.OPK.privateKey,theirIK),ecdhBits(myId.IK.privateKey,theirOPK)]);
  const pqComponent=await derivePQComponent(roomBits,'shared');
  const ikm=concat(dh1,dh2,dh3,dh4,roomBits,pqComponent);
  [dh1,dh2,dh3,dh4].forEach(wipe);wipe(pqComponent);
  const ms=await hkdfBits(ikm,'phantom-x3dh-v7-pq','master-secret',512);wipe(ikm);
  return ms;
}
class RatchetChain{constructor(root){this.chain=new Uint8Array(root);this.counter=0;}
  async step(){const msg=await hkdfBits(this.chain,'phantom-msg-key',`m:${this.counter}`,512);const next=await hkdfBits(this.chain,'phantom-chain-adv',`c:${this.counter}`,256);wipe(this.chain);this.chain=next;this.counter++;return msg;}}
async function triEnc(plain,k1,k2,k3){const iv1=rand(12),iv2=rand(12),iv3=rand(12);const c1=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv1},k1,ENC.encode(plain)));const c2=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv2},k2,c1));const c3=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv3},k3,c2));return concat(iv1,iv2,iv3,c3);}
async function triDec(buf,k1,k2,k3){const c2=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:buf.slice(24,36)},k3,buf.slice(36)));const c1=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:buf.slice(12,24)},k2,c2));return DEC.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:buf.slice(0,12)},k1,c1));}
const BLOCK=1024;
function blockPad(text,burn=false){const raw=JSON.stringify({m:text,t:Date.now(),b:burn});const need=BLOCK-(raw.length%BLOCK);return JSON.stringify({d:raw,p:b64e(rand(Math.max(1,need))).slice(0,need)});}
function blockUnpad(s){try{const i=JSON.parse(JSON.parse(s).d);return{text:strip(i.m),burn:!!i.b};}catch{return null;}}
const STEGA=/[\u200B\u200C\u200D\u200E\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD\u180E\u2028\u2029]/g;
const strip=t=>typeof t==='string'?t.replace(STEGA,''):t;

class PeerSession{
  constructor(){this.sendChain=null;this.recvChain=null;this.hmacKey=null;this.ready=false;this.seen=new Set();}
  async _setup(ms,myIk,theirIk){const a=ms.slice(0,32),b=ms.slice(32,64);const sendFirst=myIk<=theirIk;this.sendChain=new RatchetChain(sendFirst?a:b);this.recvChain=new RatchetChain(sendFirst?b:a);this.hmacKey=await hkdfHMAC(ms,'phantom-hmac-v7','auth');this.ready=true;}
  async init(myId,theirBundle,roomBits){const ms=await x3dhAgree(myId,theirBundle,roomBits);const myIk=await exportPub(myId.IK);await this._setup(ms,myIk,theirBundle.ik);wipe(ms);}
  async encrypt(envelope){
    const bits=await this.sendChain.step();
    const [k1,k2,k3]=await Promise.all([hkdfAES(bits.slice(0,32),'k1','e1'),hkdfAES(bits.slice(16,48),'k2','e2'),hkdfAES(bits.slice(32,64),'k3','e3')]);
    wipe(bits);
    const padded=blockPad(envelope);
    const ct=b64e(await triEnc(padded,k1,k2,k3));
    const n=this.sendChain.counter-1;
    const sig=await hmacSign(ENC.encode(`${n}:${ct}`),this.hmacKey);
    return{c:ct,s:sig,n};
  }
  async decrypt(pkg){
    if(!this.ready)return null;
    const{c,s,n}=pkg;
    if(typeof n!=='number'||typeof s!=='string')return null;
    if(this.seen.has(n))return null;
    this.seen.add(n);
    let ok=false;try{ok=await crypto.subtle.verify('HMAC',this.hmacKey,b64d(s),ENC.encode(`${n}:${c}`));}catch{}
    if(!ok)return null;
    try{
      const bits=await this.recvChain.step();
      const [k1,k2,k3]=await Promise.all([hkdfAES(bits.slice(0,32),'k1','e1'),hkdfAES(bits.slice(16,48),'k2','e2'),hkdfAES(bits.slice(32,64),'k3','e3')]);
      wipe(bits);
      return blockUnpad(await triDec(b64d(c),k1,k2,k3));
    }catch{return null;}
  }
}

// wire framing — replicate padPacket/unpadPacket
function padPacket(data){
  const base='{"d":'+JSON.stringify(data)+'}';
  const needed=4096-base.length;
  if(needed<=4)return base;
  const pad=b64e(rand(Math.ceil(needed*0.75))).slice(0,needed-6);
  return '{"d":'+JSON.stringify(data)+',"_":"'+pad+'"}';
}
const unpadPacket=raw=>{try{return JSON.parse(raw).d;}catch{return null;}};
const wrapPkt=obj=>padPacket(b64e(ENC.encode(JSON.stringify(obj))));
const unwrapPkt=b64str=>{try{return JSON.parse(DEC.decode(b64d(b64str)));}catch{return null;}};

const id=await new SignalIdentity().generate();
const bundle=await id.exportBundle();
const randPath=b64e(rand(8)).replace(/[+/=]/g,'').slice(0,8).toLowerCase();
const url=`ws://localhost:8787/relay/${channel}/${randPath}`;
console.log(`[peer] room="${ROOM}" channel=${channel}`);
console.log(`[peer] connecting ${url}`);
const ws=new WebSocket(url);
let session=null, peerName=null, gotConfirm=false;
const results=[];
ws.on('open',()=>{console.log('[peer] open — sending JOIN');ws.send(wrapPkt({t:'JOIN',name:MY,bundle}));});
ws.on('message',async data=>{
  const raw=typeof data==='string'?data:data.toString('utf8');
  const b64=unpadPacket(raw); if(!b64)return;
  const pkg=unwrapPkt(b64); if(!pkg||pkg.name===MY)return;
  if((pkg.t==='JOIN'||pkg.t==='HERE')&&pkg.bundle&&!session){
    peerName=pkg.name;
    session=new PeerSession();
    try{await session.init(id,pkg.bundle,ROOMBITS);}catch(e){console.log('[peer] X3DH failed:',e.message);return;}
    console.log(`[peer] ✅ symmetric X3DH session established with ${peerName}`);
    if(pkg.t==='JOIN'){ws.send(wrapPkt({t:'HERE',name:MY,bundle,to:peerName}));console.log('[peer] sent HERE');}
    const env=JSON.stringify({t:'MSG',f:MY,r:peerName,ts:Date.now(),p:'E2E-PROOF ✅ encrypted peer→app message '+Math.random().toString(36).slice(2,8),n:b64e(rand(8))});
    const payload=await session.encrypt(env);
    ws.send(wrapPkt({t:'MSG',name:MY,to:peerName,payload}));
    console.log('[peer] ✉ sent encrypted MSG (peer→app E2EE test)');
  }
  if(pkg.t==='MSG'&&pkg.payload&&session){
    const env=await session.decrypt(pkg.payload);
    if(!env){results.push('✗ app→peer: DECRYPT FAILED');console.log(results[results.length-1]);}
    else{
      const e=JSON.parse(env.text);
      if(e.t==='CONFIRM'){gotConfirm=true;results.push('✓ app→peer: decrypted app CONFIRM — E2EE both ways CONFIRMED');}
      else results.push(`✓ app→peer: decrypted MSG "${String(e.p).slice(0,50)}"`);
      console.log(results[results.length-1]);
    }
  }
});
ws.on('close',(code)=>console.log(`[peer] closed code=${code}`));
ws.on('error',e=>console.log('[peer] error:',e.message));
setTimeout(()=>{
  console.log('=== PEER RESULTS ===');
  console.log(results.join('\n')||'(no inbound messages)');
  console.log('app→peer CONFIRM decrypted:', gotConfirm?'YES':'NO');
  process.exit(0);
},15000);
