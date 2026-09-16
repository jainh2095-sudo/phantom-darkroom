// Temporary: verifies the PeerSession fix by replicating the app's crypto
// (Node 24 global Web Crypto). Uses a symmetric key agreement so BOTH peers
// derive the same master secret regardless of who initiates (handles the
// simultaneous-join case too).
const ENC = new TextEncoder();
const DEC = new TextDecoder();
function b64e(buf){const bytes=buf instanceof Uint8Array?buf:new Uint8Array(buf);let o="";for(let i=0;i<bytes.length;i+=4096)o+=String.fromCharCode(...bytes.subarray(i,i+4096));return btoa(o);}
function b64d(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
function rand(n){return crypto.getRandomValues(new Uint8Array(n));}
function wipe(arr){if(arr instanceof Uint8Array)arr.fill(0);else if(Array.isArray(arr))arr.fill(0);}
function concat(...arrs){const o=new Uint8Array(arrs.reduce((s,a)=>s+a.length,0));let off=0;for(const a of arrs){o.set(a,off);off+=a.length;}return o;}
async function genKeypair(){return crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey","deriveBits"]);}
async function exportPub(kp){return b64e(await crypto.subtle.exportKey("raw",kp.publicKey));}
async function importPub(b64){return crypto.subtle.importKey("raw",b64d(b64),{name:"ECDH",namedCurve:"P-256"},false,[]);}
async function ecdhBits(priv,pub){return new Uint8Array(await crypto.subtle.deriveBits({name:"ECDH",public:pub},priv,256));}
async function hkdfBits(km,salt,info,bits=512){const b=await crypto.subtle.importKey("raw",km,"HKDF",false,["deriveBits"]);return new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-512",salt:ENC.encode(salt),info:ENC.encode(info)},b,bits));}
async function hkdfAES(km,salt,info){const b=await crypto.subtle.importKey("raw",km,"HKDF",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-512",salt:ENC.encode(salt),info:ENC.encode(info)},b,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);}
async function hkdfHMAC(km,salt,info){const b=await crypto.subtle.importKey("raw",km,"HKDF",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-512",salt:ENC.encode(salt),info:ENC.encode(info)},b,{name:"HMAC",hash:"SHA-512",length:512},false,["sign","verify"]);}
async function hmacSign(data,key){return b64e(await crypto.subtle.sign("HMAC",key,data instanceof Uint8Array?data:ENC.encode(data)));}
async function hmacVerify(data,sig,key){try{if(typeof sig!=="string"||sig.length===0)return false;return await crypto.subtle.verify("HMAC",key,b64d(sig),data instanceof Uint8Array?data:ENC.encode(data));}catch{return false;}}
class SignalIdentity{constructor(){this.IK=null;this.SPK=null;this.OPK=null;this.SPKsig=null;}async generate(){this.IK=await genKeypair();this.SPK=await genKeypair();this.OPK=await genKeypair();const ikBits=await ecdhBits(this.IK.privateKey,await importPub(await exportPub(this.IK)));const hmacKey=await hkdfHMAC(ikBits,"phantom-ik-sign","spk-signature");this.SPKsig=await crypto.subtle.sign("HMAC",hmacKey,b64d(await exportPub(this.SPK)));return this;}async exportBundle(){return{ik:await exportPub(this.IK),spk:await exportPub(this.SPK),spkSig:b64e(this.SPKsig),opk:await exportPub(this.OPK)};}}
async function derivePQComponent(roomBits,context){return hkdfBits(roomBits,"phantom-pq-v7",context+":pq-hardening",512);}
// Symmetric agreement: both peers compute the SAME 4 DH values (ordered by the
// two identity keys) so the master secret matches no matter who initiates.
async function x3dhAgree(myId,theirBundle,roomBits){
  const myIk=await exportPub(myId.IK),theirIk=theirBundle.ik;
  const forward=myIk<=theirIk;
  const theirSPK=await importPub(theirBundle.spk),theirOPK=await importPub(theirBundle.opk),theirIK=await importPub(theirIk);
  const mySPKp=await importPub(await exportPub(myId.SPK)),myOPKp=await importPub(await exportPub(myId.OPK));
  const [dh1,dh2,dh3,dh4]=forward
    ? await Promise.all([ecdhBits(myId.IK.privateKey,theirSPK),ecdhBits(myId.SPK.privateKey,theirIK),ecdhBits(myId.IK.privateKey,theirOPK),ecdhBits(myId.OPK.privateKey,theirIK)])
    : await Promise.all([ecdhBits(myId.SPK.privateKey,theirIK),ecdhBits(myId.IK.privateKey,theirSPK),ecdhBits(myId.OPK.privateKey,theirIK),ecdhBits(myId.IK.privateKey,theirOPK)]);
  const pqComponent=await derivePQComponent(roomBits,"shared");
  const ikm=concat(dh1,dh2,dh3,dh4,roomBits,pqComponent);
  [dh1,dh2,dh3,dh4].forEach(wipe);wipe(pqComponent);
  const ms=await hkdfBits(ikm,"phantom-x3dh-v7-pq","master-secret",512);wipe(ikm);return ms;
}
class RatchetChain{constructor(root){this.chain=new Uint8Array(root);this.counter=0;}async step(){const msg=await hkdfBits(this.chain,"phantom-msg-key",`m:${this.counter}`,512);const next=await hkdfBits(this.chain,"phantom-chain-adv",`c:${this.counter}`,256);wipe(this.chain);this.chain=next;this.counter++;return msg;}}
async function triEnc(plain,k1,k2,k3){const iv1=rand(12),iv2=rand(12),iv3=rand(12);const c1=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv1},k1,ENC.encode(plain)));const c2=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv2},k2,c1));const c3=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv3},k3,c2));return concat(iv1,iv2,iv3,c3);}
async function triDec(buf,k1,k2,k3){const c2=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:buf.slice(24,36)},k3,buf.slice(36)));const c1=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:buf.slice(12,24)},k2,c2));return DEC.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:buf.slice(0,12)},k1,c1));}
const BLOCK=1024;
function blockPad(text){const raw=JSON.stringify({m:text,t:Date.now(),b:false});const need=BLOCK-(raw.length%BLOCK);return JSON.stringify({d:raw,p:b64e(rand(Math.max(1,need))).slice(0,need)});}
function blockUnpad(s){try{const i=JSON.parse(JSON.parse(s).d);return{text:i.m,burnOnRead:!!i.b};}catch{return null;}}
class PeerSession{constructor(){this.sendChain=null;this.recvChain=null;this.hmacKey=null;this.ready=false;this.seen=new Set();this.sendSeq=0;this.recvSeq=0;}
  async _setup(ms,myIk,theirIk){const a=ms.slice(0,32),b=ms.slice(32,64);const sendFirst=myIk<=theirIk;this.sendChain=new RatchetChain(sendFirst?a:b);this.recvChain=new RatchetChain(sendFirst?b:a);this.hmacKey=await hkdfHMAC(ms,"phantom-hmac-v7","auth");this.ready=true;}
  async initAsInitiator(myId,theirBundle,roomBits){const ms=await x3dhAgree(myId,theirBundle,roomBits);const myIk=await exportPub(myId.IK);await this._setup(ms,myIk,theirBundle.ik);wipe(ms);}
  async initAsResponder(myId,theirBundle,roomBits){const ms=await x3dhAgree(myId,theirBundle,roomBits);const myIk=await exportPub(myId.IK);await this._setup(ms,myIk,theirBundle.ik);wipe(ms);}
  async encrypt(envelope){if(!this.ready)throw new Error("no session");this.sendSeq++;const bits=await this.sendChain.step();const[k1,k2,k3]=await Promise.all([hkdfAES(bits.slice(0,32),"k1","e1"),hkdfAES(bits.slice(16,48),"k2","e2"),hkdfAES(bits.slice(32,64),"k3","e3")]);wipe(bits);const padded=blockPad(envelope);const ct=b64e(await triEnc(padded,k1,k2,k3));const n=this.sendChain.counter-1;const sig=await hmacSign(ENC.encode(`${n}:${ct}`),this.hmacKey);return{c:ct,s:sig,n};}
  async decrypt(pkg){if(!this.ready)return null;const{c,s,n}=pkg;if(typeof n!=="number"||typeof s!=="string")return null;if(this.seen.has(n)||n<this.recvChain.counter-100)return null;this.seen.add(n);if(this.seen.size>500){const a=[...this.seen].sort((x,y)=>x-y);a.slice(0,200).forEach(v=>this.seen.delete(v));}if(!await hmacVerify(ENC.encode(`${n}:${c}`),s,this.hmacKey))return null;try{this.recvSeq++;const bits=await this.recvChain.step();const[k1,k2,k3]=await Promise.all([hkdfAES(bits.slice(0,32),"k1","e1"),hkdfAES(bits.slice(16,48),"k2","e2"),hkdfAES(bits.slice(32,64),"k3","e3")]);wipe(bits);return blockUnpad(await triDec(b64d(c),k1,k2,k3));}catch{return null;}}}
function buildEnvelope(type,from,to,payload){return JSON.stringify({t:type,f:from,r:to,ts:Date.now(),p:payload,n:b64e(rand(8))});}

async function roundtrip(label,sA,sB,aName,bName){
  const da=await sB.decrypt(await sA.encrypt(buildEnvelope("txt",aName,bName,"hello from A")));
  const db=await sA.decrypt(await sB.encrypt(buildEnvelope("txt",bName,aName,"reply from B")));
  const ok=da&&db&&da.text.includes("hello from A")&&db.text.includes("reply from B");
  console.log(`${label}: A->B ${da?"OK":"FAIL"} | B->A ${db?"OK":"FAIL"} => ${ok?"PASS":"FAIL"}`);
  return ok;
}
async function main(){
  const roomBits=new Uint8Array(64).fill(7);
  {const idA=await new SignalIdentity().generate(),idB=await new SignalIdentity().generate();const bA=await idA.exportBundle(),bB=await idB.exportBundle();const sA=new PeerSession(),sB=new PeerSession();await sA.initAsInitiator(idA,bB,roomBits);await sB.initAsResponder(idB,bA,roomBits);await roundtrip("Scenario 1 (initiator/responder)",sA,sB,"A","B");}
  {const idA=await new SignalIdentity().generate(),idB=await new SignalIdentity().generate();const bA=await idA.exportBundle(),bB=await idB.exportBundle();const sA=new PeerSession(),sB=new PeerSession();await sA.initAsInitiator(idA,bB,roomBits);await sB.initAsInitiator(idB,bA,roomBits);await roundtrip("Scenario 2 (simultaneous initiators)",sA,sB,"A","B");}
  process.exit(0);
}
main();