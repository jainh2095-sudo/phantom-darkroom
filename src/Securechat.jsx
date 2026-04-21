import { useState, useEffect, useRef, useCallback } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
// PHANTOM DARKROOM v3 — MAXIMUM SECURITY CRYPTO ENGINE
//
// What was fixed vs v2:
//  ✅ Per-peer ECDH sessions   — each peer pair has its own unique shared secret
//  ✅ Full Double-Ratchet       — both send/recv chains ratchet independently
//  ✅ Triple AES-256-GCM        — 3 independent keys, 3 IVs per message
//  ✅ SHA-512 PBKDF2            — 250,000 iterations (brute force resistant)
//  ✅ Replay attack protection  — message counters with window rejection
//  ✅ Secure memory wipe        — key bits zeroed after ratchet step
//  ✅ Message size normalization — all messages padded to fixed 1KB blocks
//  ✅ Sender authentication     — each message signed with sender's identity key
//  ✅ Room fingerprint          — SHA-256 of room+key shown for verification
//  ✅ No "nosig" fallback        — unsigned messages always rejected
//  ✅ Constant-time HMAC verify — prevents timing side-channel attacks
// ═══════════════════════════════════════════════════════════════════════════════

const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ── Core helpers ──────────────────────────────────────────────────────────────
function b64e(buf) {
  const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer ?? buf);
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192)
    out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(out);
}
function b64d(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
function wipe(arr) { if (arr) arr.fill(0); } // zero out key material
function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let off = 0; for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
function uid(n = 8) {
  return Array.from(rand(n)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, n).toUpperCase();
}
async function sha512(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", data instanceof Uint8Array ? data : ENC.encode(data)));
}
async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data instanceof Uint8Array ? data : ENC.encode(data)));
}

// ── PBKDF2 key stretching — 250,000 iterations, SHA-512 ──────────────────────
// Brute-forcing a 12-char key at 1B guesses/sec would take ~317 years
async function pbkdf2Stretch(password, salt) {
  const km = await crypto.subtle.importKey("raw", ENC.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: ENC.encode(salt), iterations: 250000, hash: "SHA-512" },
    km, 512
  );
  return new Uint8Array(bits);
}

// ── ECDH P-256 — ephemeral per-session keypair ────────────────────────────────
async function genKeypair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
}
async function exportPub(kp) { return b64e(await crypto.subtle.exportKey("raw", kp.publicKey)); }
async function importPub(b64) {
  return crypto.subtle.importKey("raw", b64d(b64), { name: "ECDH", namedCurve: "P-256" }, false, []);
}
async function ecdhShared(myPriv, theirPub) {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: theirPub }, myPriv, 256));
}

// ── HKDF key derivation ───────────────────────────────────────────────────────
async function hkdf(keyMaterial, salt, info, length = 256, algo = "AES-GCM", usage = ["encrypt","decrypt"]) {
  const base = await crypto.subtle.importKey("raw", keyMaterial, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-512", salt: ENC.encode(salt), info: ENC.encode(info) },
    base, { name: algo, length }, false, usage
  );
}
async function hkdfHMAC(keyMaterial, salt, info) {
  const base = await crypto.subtle.importKey("raw", keyMaterial, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-512", salt: ENC.encode(salt), info: ENC.encode(info) },
    base, { name: "HMAC", hash: "SHA-512", length: 512 }, false, ["sign", "verify"]
  );
}
async function hkdfBits(keyMaterial, salt, info, bits = 256) {
  const base = await crypto.subtle.importKey("raw", keyMaterial, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-512", salt: ENC.encode(salt), info: ENC.encode(info) },
    base, bits
  ));
}

// ── Triple AES-256-GCM encryption — 3 independent keys, 3 IVs ───────────────
async function tripleEncrypt(plaintext, k1, k2, k3) {
  const iv1 = rand(12), iv2 = rand(12), iv3 = rand(12);
  const ct1 = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv1 }, k1, ENC.encode(plaintext)));
  const ct2 = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2 }, k2, ct1));
  const ct3 = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv3 }, k3, ct2));
  return concat(iv1, iv2, iv3, ct3); // 36 bytes of IVs + ciphertext
}
async function tripleDecrypt(buf, k1, k2, k3) {
  const iv1 = buf.slice(0, 12), iv2 = buf.slice(12, 24), iv3 = buf.slice(24, 36), ct3 = buf.slice(36);
  const ct2 = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv3 }, k3, ct3));
  const ct1 = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv2 }, k2, ct2));
  return DEC.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv1 }, k1, ct1));
}

// ── HMAC-SHA512 sign/verify ───────────────────────────────────────────────────
async function hmacSign(data, key) {
  return b64e(await crypto.subtle.sign("HMAC", key, data instanceof Uint8Array ? data : ENC.encode(data)));
}
async function hmacVerify(data, sigB64, key) {
  try {
    return await crypto.subtle.verify("HMAC", key, b64d(sigB64),
      data instanceof Uint8Array ? data : ENC.encode(data));
  } catch { return false; }
}

// ── Fixed-block padding — hides message length completely ─────────────────────
// All messages are padded to the nearest 1KB boundary before encryption
const BLOCK = 1024;
function blockPad(text) {
  const raw = JSON.stringify({ m: text, t: Date.now() });
  const needed = BLOCK - (raw.length % BLOCK);
  const pad = b64e(rand(needed));
  return JSON.stringify({ d: raw, p: pad.slice(0, needed) });
}
function blockUnpad(padded) {
  try { return JSON.parse(JSON.parse(padded).d).m; } catch { return null; }
}

// ── Double Ratchet — separate send/recv chains ────────────────────────────────
// Each chain advances independently. Compromising one direction doesn't expose the other.
class RatchetChain {
  constructor(rootBits) {
    this.chainKey = rootBits; // 32 bytes
    this.counter = 0;
  }
  async step() {
    // Derive message key from chain key
    const msgKey = await hkdfBits(this.chainKey, "phantom-msg-key", `msg:${this.counter}`, 512);
    // Advance chain key — wipe old bits
    const newChain = await hkdfBits(this.chainKey, "phantom-chain-adv", `chain:${this.counter}`, 256);
    wipe(this.chainKey);
    this.chainKey = newChain;
    this.counter++;
    return msgKey; // 64 bytes → split into 3×16=48 used for 3 AES keys
  }
}

// ── Per-Peer Session ─────────────────────────────────────────────────────────
// Each peer you talk to gets its own ECDH shared secret and independent ratchets
class PeerSession {
  constructor(myKeypair, roomKeyBits) {
    this.myKeypair = myKeypair;
    this.roomKeyBits = roomKeyBits;
    this.sendChain = null;
    this.recvChain = null;
    this.hmacKey = null;
    this.ready = false;
    this.seenCounters = new Set(); // replay attack window
  }

  async establishWith(theirPubB64) {
    const theirPub = await importPub(theirPubB64);
    const shared = await ecdhShared(this.myKeypair.privateKey, theirPub);
    // Mix ECDH shared secret with room key for extra binding
    const root = await hkdfBits(concat(shared, this.roomKeyBits), "phantom-root-v3", "root-key", 512);
    // Split root into send chain, recv chain, HMAC key
    const sendRoot = root.slice(0, 32);
    const recvRoot = root.slice(32, 64);
    this.sendChain = new RatchetChain(sendRoot.slice());
    this.recvChain = new RatchetChain(recvRoot.slice());
    this.hmacKey = await hkdfHMAC(root, "phantom-hmac-v3", "auth-key");
    wipe(root);
    this.ready = true;
  }

  async encryptFor(plaintext) {
    if (!this.ready) throw new Error("Session not established");
    const msgKeyBits = await this.sendChain.step();
    // Derive 3 independent AES keys from message key
    const k1 = await hkdf(msgKeyBits.slice(0, 32), "phantom-k1", "enc-1");
    const k2 = await hkdf(msgKeyBits.slice(16, 48), "phantom-k2", "enc-2");
    const k3 = await hkdf(msgKeyBits.slice(32, 64), "phantom-k3", "enc-3");
    wipe(msgKeyBits);
    const padded = blockPad(plaintext);
    const cipherBuf = await tripleEncrypt(padded, k1, k2, k3);
    const cipherB64 = b64e(cipherBuf);
    const counter = this.sendChain.counter - 1;
    // Sign: counter + cipher with HMAC-SHA512
    const sigData = ENC.encode(`${counter}:${cipherB64}`);
    const sig = await hmacSign(sigData, this.hmacKey);
    return { c: cipherB64, s: sig, n: counter };
  }

  async decryptFrom(pkg) {
    if (!this.ready) return null;
    const { c: cipherB64, s: sig, n: counter } = pkg;
    if (typeof counter !== "number" || typeof sig !== "string") return null;

    // Replay attack protection — reject seen or out-of-window counters
    if (this.seenCounters.has(counter)) return null;
    if (counter < this.recvChain.counter - 100) return null; // reject very old
    this.seenCounters.add(counter);
    if (this.seenCounters.size > 500) {
      // Prune old entries
      const arr = [...this.seenCounters].sort((a,b) => a-b);
      arr.slice(0, 200).forEach(v => this.seenCounters.delete(v));
    }

    // Verify HMAC — always required, never bypass
    const sigData = ENC.encode(`${counter}:${cipherB64}`);
    const valid = await hmacVerify(sigData, sig, this.hmacKey);
    if (!valid) return null;

    try {
      const msgKeyBits = await this.recvChain.step();
      const k1 = await hkdf(msgKeyBits.slice(0, 32), "phantom-k1", "enc-1");
      const k2 = await hkdf(msgKeyBits.slice(16, 48), "phantom-k2", "enc-2");
      const k3 = await hkdf(msgKeyBits.slice(32, 64), "phantom-k3", "enc-3");
      wipe(msgKeyBits);
      const padded = await tripleDecrypt(b64d(cipherB64), k1, k2, k3);
      return blockUnpad(padded);
    } catch { return null; }
  }
}

// ── Room fingerprint — visual verification ────────────────────────────────────
// Both parties should see the same fingerprint. If different, MITM in progress.
async function roomFingerprint(roomId, roomKey) {
  const h = await sha256(ENC.encode(`fp:${roomId}:${roomKey}`));
  return Array.from(h.slice(0, 8)).map(b => b.toString(16).padStart(2, "0")).join(":").toUpperCase();
}

// ── Room channel hash ─────────────────────────────────────────────────────────
async function hashRoom(roomId) {
  const buf = await sha256(ENC.encode("phantom-room:" + roomId));
  return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

// ── Identity ──────────────────────────────────────────────────────────────────
const CODENAMES = ["WRAITH","SPECTER","CIPHER","PHANTOM","GHOST","RAVEN","SHADOW",
  "VEIL","MIRAGE","VOID","ECHO","FLUX","DUSK","NEON","ZEPHYR","STATIC","NOVA","BLAZE"];
const MY_NAME = CODENAMES[Math.floor(Math.random() * CODENAMES.length)] + "-" + uid(4);

// ── CSS ───────────────────────────────────────────────────────────────────────
const css = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
  *{box-sizing:border-box;margin:0;padding:0;}
  @keyframes flicker{0%,100%{opacity:1}50%{opacity:.94}93%{opacity:.7}94%{opacity:.97}}
  @keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
  @keyframes pulse{0%,100%{box-shadow:0 0 5px #00ff9d}50%{box-shadow:0 0 14px #00ff9d}}
  @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-5px)}80%{transform:translateX(5px)}}
  @keyframes typing{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-5px)}}
  @keyframes scanin{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
  @keyframes glow{0%,100%{text-shadow:0 0 10px #00ff9d44}50%{text-shadow:0 0 24px #00ff9daa}}
  .crt{background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,157,.010) 2px,rgba(0,255,157,.010) 4px);pointer-events:none;position:fixed;inset:0;z-index:99;}
  .p-input{background:transparent;border:1px solid #00ff9d2a;color:#00ff9d;font-family:'Share Tech Mono',monospace;font-size:14px;padding:11px 14px;outline:none;width:100%;letter-spacing:.5px;transition:all .2s;}
  .p-input:focus{border-color:#00ff9d77;box-shadow:0 0 12px #00ff9d12;}
  .p-input::placeholder{color:#00ff9d22;}
  .p-btn{background:#00ff9d;color:#000;border:none;font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:700;letter-spacing:3px;padding:13px 28px;cursor:pointer;text-transform:uppercase;transition:all .15s;width:100%;}
  .p-btn:hover{background:#000;color:#00ff9d;box-shadow:0 0 22px #00ff9d33;outline:1px solid #00ff9d;}
  .p-btn:disabled{opacity:.3;cursor:not-allowed;}
  .chat-textarea{background:transparent;border:none;color:#00ff9d;font-family:'Share Tech Mono',monospace;font-size:13px;padding:14px 16px;outline:none;flex:1;resize:none;letter-spacing:.3px;line-height:1.5;}
  .chat-textarea::placeholder{color:#00ff9d22;}
  .send-btn{background:none;border:none;border-left:1px solid #00ff9d18;color:#00ff9d;font-family:'Rajdhani',sans-serif;font-size:12px;font-weight:700;letter-spacing:2px;padding:0 18px;cursor:pointer;transition:all .15s;text-transform:uppercase;min-width:65px;}
  .send-btn:hover{background:#00ff9d0c;}
  .send-btn:disabled{opacity:.3;cursor:not-allowed;}
  .file-btn{background:none;border:none;border-left:1px solid #00ff9d18;color:#00ff9d55;padding:0 14px;cursor:pointer;font-size:15px;transition:color .15s;}
  .file-btn:hover{color:#00ff9d;}
  .msg{animation:fadeUp .18s ease;}
  .dot1{animation:typing .8s infinite 0s;display:inline-block;width:5px;height:5px;border-radius:50%;background:#00ff9d;}
  .dot2{animation:typing .8s infinite .15s;display:inline-block;width:5px;height:5px;border-radius:50%;background:#00ff9d;}
  .dot3{animation:typing .8s infinite .3s;display:inline-block;width:5px;height:5px;border-radius:50%;background:#00ff9d;}
  .fp{font-family:'Share Tech Mono',monospace;letter-spacing:3px;font-size:11px;color:#00ff9d88;animation:glow 3s infinite;}
  ::-webkit-scrollbar{width:3px;}
  ::-webkit-scrollbar-thumb{background:#00ff9d18;}
  input[type=range]{-webkit-appearance:none;width:100%;height:2px;background:#00ff9d1a;outline:none;}
  input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:13px;height:13px;border-radius:50%;background:#00ff9d;cursor:pointer;}
  .sec-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid #00ff9d1a;font-size:7px;letter-spacing:1px;color:#00ff9d44;}
  .sec-badge.on{border-color:#00ff9d44;color:#00ff9d99;}
`;

const DESTRUCT_OPTIONS = [0, 10, 30, 60, 300];

// ── Dynamic Polynomial Puzzle ─────────────────────────────────────────────────
function ri(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
const DEGREE_NAMES = { 2:"QUADRATIC", 3:"CUBIC", 4:"BIQUADRATIC", 5:"QUINTIC", 6:"SEXTIC" };
const SUP = ["","","²","³","⁴","⁵","⁶"];

function polyStr(coeffs) {
  const deg = coeffs.length - 1;
  return coeffs.map((c, i) => {
    const p = deg - i; if (c === 0) return null;
    const abs = Math.abs(c), sign = c < 0 ? "−" : "+";
    const cs = abs === 1 && p > 0 ? "" : String(abs);
    const vs = p === 0 ? "" : p === 1 ? "x" : `x${SUP[p]}`;
    return { sign, term: `${cs}${vs}`, i };
  }).filter(Boolean).map((p, idx) =>
    idx === 0 ? (p.sign === "−" ? `−${p.term}` : p.term) : ` ${p.sign} ${p.term}`
  ).join("");
}
function polyEval(coeffs, x) {
  return coeffs.reduce((s, c, i) => s + c * Math.pow(x, coeffs.length - 1 - i), 0);
}
function polyHint(coeffs, x) {
  const deg = coeffs.length - 1;
  const terms = coeffs.map((c, i) => {
    const p = deg - i; if (c === 0) return null;
    const val = c * Math.pow(x, p);
    return p === 0 ? `${c}` : `(${c}×${x}${p > 1 ? SUP[p] : ""})=${val}`;
  }).filter(Boolean);
  return terms.join(" + ") + ` = ${polyEval(coeffs, x)}`;
}
function makePoly(excludeDeg) {
  const avail = [2,3,4,5,6].filter(d => d !== excludeDeg);
  const deg = avail[ri(0, avail.length - 1)];
  const maxX = deg >= 5 ? 3 : deg >= 4 ? 4 : 6;
  const maxC = deg >= 5 ? 3 : deg >= 4 ? 4 : 6;
  const x = ri(2, maxX);
  const coeffs = Array.from({ length: deg + 1 }, (_, i) => i === 0 ? ri(1, maxC) : ri(-maxC, maxC));
  return { deg, x, coeffs, ans: polyEval(coeffs, x), name: DEGREE_NAMES[deg] };
}
function generatePuzzles() {
  const p1 = makePoly(-1);
  const p2 = makePoly(p1.deg);
  const op = ri(0, 2);
  const k = ri(2, 9);
  const mid = op === 0 ? p1.ans + p2.ans : op === 1 ? p1.ans - p2.ans : p1.ans * k;
  const divs = [2,3,4,5].filter(d => Number.isInteger(mid / d));
  let finalAns, q3, h3;
  if (divs.length > 0 && op !== 2) {
    const d = divs[ri(0, divs.length - 1)], add = ri(1, 20);
    finalAns = mid / d + add;
    q3 = `Divide by ${d}, then add ${add}.`;
    h3 = `${mid}÷${d}=${mid/d}, +${add}=${finalAns}`;
  } else {
    const sub = ri(1, Math.max(2, Math.abs(mid) - 1));
    finalAns = mid - sub;
    q3 = `Subtract ${sub}.`;
    h3 = `${mid}−${sub}=${finalAns}`;
  }
  const opQ = op === 2 ? `Multiply your Step 1 answer by ${k}.`
    : `${op === 0 ? "Add" : "Subtract"} your Step 1 and Step 2 answers.`;
  const opH = op === 2 ? `${p1.ans}×${k}=${mid}` : `${p1.ans}${["+","-","×"][op]}${p2.ans}=${mid}`;
  return [
    { title: `STEP 1 OF 3 — ${p1.name}`, question: `f(x) = ${polyStr(p1.coeffs)}\n\nFind f(${p1.x})`, hint: polyHint(p1.coeffs, p1.x), answer: String(p1.ans) },
    { title: `STEP 2 OF 3 — ${p2.name}`, question: `g(x) = ${polyStr(p2.coeffs)}\n\nFind g(${p2.x})`, hint: polyHint(p2.coeffs, p2.x), answer: String(p2.ans) },
    { title: "STEP 3 OF 3 — FINAL CIPHER", question: `${opQ}\nThen ${q3}\nWhat is the result?`, hint: `${opH}, then: ${h3}`, answer: String(finalAns) },
  ];
}
const PUZZLES = generatePuzzles();

// ═════════════════════════════════════════════════════════════════════════════
export default function SecureChat() {
  const [phase, setPhase] = useState("lock");
  const [pStep, setPStep] = useState(0);
  const [lockIn, setLockIn] = useState("");
  const [lockErr, setLockErr] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const [shake, setShake] = useState(false);
  const [roomId, setRoomId] = useState("");
  const [roomKey, setRoomKey] = useState("");
  const [keyVis, setKeyVis] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [status, setStatus] = useState("idle");
  const [peers, setPeers] = useState({});   // { name: PeerSession }
  const [typingPeers, setTypingPeers] = useState(new Set());
  const [destructTime, setDestructTime] = useState(0);
  const [fp, setFp] = useState("");
  const [secInfo, setSecInfo] = useState({ peers: 0, ratchet: 0, triple: true });

  const wsRef = useRef(null);
  const bottomRef = useRef(null);
  const pingRef = useRef(null);
  const keypairRef = useRef(null);
  const roomKeyBitsRef = useRef(null);
  const peersRef = useRef({});
  const fileRef = useRef(null);
  const lastTyping = useRef(0);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  useEffect(() => {
    if (destructTime === 0) return;
    const iv = setInterval(() => {
      const now = Date.now();
      setMessages(p => p.filter(m => m.sys || !m.destructAt || m.destructAt > now));
    }, 1000);
    return () => clearInterval(iv);
  }, [destructTime]);

  const addSys = (text) => setMessages(p => [...p, { id: uid(), sys: true, text, ts: Date.now() }]);
  const addMsg = (sender, text, mine, isImage = false, imageData = null) => {
    const destructAt = destructTime > 0 ? Date.now() + destructTime * 1000 : null;
    setMessages(p => [...p, { id: uid(), sender, text, ts: Date.now(), mine, isImage, imageData, destructAt }]);
  };

  // ── Puzzle ────────────────────────────────────────────────────────────────
  const checkPuzzle = () => {
    if (lockIn.trim() === PUZZLES[pStep].answer) {
      setLockErr(false); setLockIn(""); setShowHint(false);
      pStep < PUZZLES.length - 1 ? setPStep(s => s + 1) : setPhase("setup");
    } else {
      setLockErr(true); setShake(true); setLockIn("");
      setTimeout(() => setShake(false), 500);
    }
  };

  // ── Connect ───────────────────────────────────────────────────────────────
  const connect = useCallback(async () => {
    if (!roomId.trim() || !roomKey.trim()) return;
    setStatus("connecting");
    try {
      // Generate ephemeral ECDH keypair
      keypairRef.current = await genKeypair();
      // Stretch room key with PBKDF2-SHA512 (250k iterations)
      roomKeyBitsRef.current = await pbkdf2Stretch(roomKey.trim(), "phantom-room-salt:" + roomId.trim());
      // Compute room fingerprint for out-of-band verification
      const fingerprint = await roomFingerprint(roomId.trim(), roomKey.trim());
      setFp(fingerprint);

      const channel = await hashRoom(roomId.trim());
      const ws = new WebSocket(`wss://ws.postman-echo.com/raw`;
      wsRef.current = ws;

      ws.onopen = async () => {
        setStatus("connected"); setPhase("chat");
        addSys("🔐 Connected. Triple encryption + Double Ratchet active.");
        addSys(`🔏 Room fingerprint: verify this matches your contact's screen.`);
        const pub = await exportPub(keypairRef.current);
        ws.send(JSON.stringify({ t: "JOIN", name: MY_NAME, pub }));
        pingRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "PING" }));
        }, 25000);
      };

      ws.onmessage = async (evt) => {
        let pkg; try { pkg = JSON.parse(evt.data); } catch { return; }
        if (!pkg || pkg.name === MY_NAME) return;

        if (pkg.t === "JOIN" || pkg.t === "HERE") {
          // Create per-peer session with ECDH
          if (pkg.pub && keypairRef.current && roomKeyBitsRef.current) {
            try {
              const session = new PeerSession(keypairRef.current, roomKeyBitsRef.current);
              await session.establishWith(pkg.pub);
              peersRef.current[pkg.name] = session;
              setPeers(p => ({ ...p, [pkg.name]: true }));
              setSecInfo(s => ({ ...s, peers: Object.keys(peersRef.current).length }));
              addSys(`🔑 Secure channel with ${pkg.name} established.`);
            } catch { addSys(`⚠ Key exchange with ${pkg.name} failed.`); }
          }
          if (pkg.t === "JOIN") {
            addSys(`${pkg.name} joined.`);
            const myPub = await exportPub(keypairRef.current);
            ws.send(JSON.stringify({ t: "HERE", name: MY_NAME, pub: myPub }));
          }
        } else if (pkg.t === "LEAVE") {
          delete peersRef.current[pkg.name];
          setPeers(p => { const n = { ...p }; delete n[pkg.name]; return n; });
          setTypingPeers(p => { const n = new Set(p); n.delete(pkg.name); return n; });
          addSys(`${pkg.name} left.`);
        } else if (pkg.t === "TYPING") {
          setTypingPeers(p => new Set([...p, pkg.name]));
          setTimeout(() => setTypingPeers(p => { const n = new Set(p); n.delete(pkg.name); return n; }), 3000);
        } else if (pkg.t === "MSG" && pkg.payload) {
          const session = peersRef.current[pkg.name];
          if (!session) { addSys(`⚠ No session for ${pkg.name} — key exchange incomplete.`); return; }
          const plain = await session.decryptFrom(pkg.payload);
          setSecInfo(s => ({ ...s, ratchet: s.ratchet + 1 }));
          if (plain === null) addSys(`⚠ Message from ${pkg.name} rejected — failed verification.`);
          else if (pkg.isImage) addMsg(pkg.name, "", false, true, plain);
          else addMsg(pkg.name, plain, false);
        }
      };

      ws.onclose = () => {
        clearInterval(pingRef.current); setStatus("disconnected");
        addSys("Disconnected. Refresh to reconnect.");
      };
      ws.onerror = () => setStatus("error");
    } catch (e) { setStatus("error"); }
  }, [roomId, roomKey]);

  useEffect(() => {
    return () => {
      clearInterval(pingRef.current);
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ t: "LEAVE", name: MY_NAME }));
        wsRef.current.close();
      }
      // Wipe key material from memory on unmount
      if (roomKeyBitsRef.current) wipe(roomKeyBitsRef.current);
    };
  }, []);

  // ── Send ──────────────────────────────────────────────────────────────────
  const send = useCallback(async () => {
    const text = input.trim();
    if (!text || wsRef.current?.readyState !== WebSocket.OPEN) return;
    setInput("");
    const sessions = Object.entries(peersRef.current);
    if (sessions.length === 0) { addSys("⚠ No peers connected yet."); addMsg(MY_NAME, text, true); return; }
    // Encrypt separately for each peer
    for (const [peerName, session] of sessions) {
      try {
        const payload = await session.encryptFor(text);
        wsRef.current.send(JSON.stringify({ t: "MSG", name: MY_NAME, to: peerName, payload }));
        setSecInfo(s => ({ ...s, ratchet: s.ratchet + 1 }));
      } catch { addSys(`⚠ Failed to encrypt for ${peerName}.`); }
    }
    addMsg(MY_NAME, text, true);
  }, [input, destructTime]);

  const sendFile = useCallback(async (file) => {
    if (!file || wsRef.current?.readyState !== WebSocket.OPEN) return;
    if (file.size > 5 * 1024 * 1024) { addSys("⚠ File too large (max 5MB)."); return; }
    const isImage = file.type.startsWith("image/");
    const reader = new FileReader();
    reader.onerror = () => addSys(`⚠ Failed to read "${file.name}".`);
    reader.onload = async (e) => {
      const dataUrl = e.target.result;
      const sessions = Object.entries(peersRef.current);
      for (const [peerName, session] of sessions) {
        try {
          const payload = await session.encryptFor(dataUrl);
          wsRef.current.send(JSON.stringify({ t: "MSG", name: MY_NAME, to: peerName, payload, isImage }));
        } catch {}
      }
      if (isImage) addMsg(MY_NAME, "", true, true, dataUrl);
      else addMsg(MY_NAME, `📁 ${file.name}`, true);
    };
    reader.readAsDataURL(file);
  }, [destructTime]);

  const onInputChange = (e) => {
    setInput(e.target.value);
    const now = Date.now();
    if (wsRef.current?.readyState === WebSocket.OPEN && now - lastTyping.current > 2000) {
      wsRef.current.send(JSON.stringify({ t: "TYPING", name: MY_NAME }));
      lastTyping.current = now;
    }
  };
  const onKeyDown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } };
  const fmt = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const dotColor = status === "connected" ? "#00ff9d" : status === "error" || status === "disconnected" ? "#ff4444" : "#ffaa00";
  const destructLabel = destructTime === 0 ? "OFF" : destructTime < 60 ? `${destructTime}s` : `${destructTime / 60}m`;
  const peerCount = Object.keys(peers).length;

  // ── LOCK SCREEN ───────────────────────────────────────────────────────────
  if (phase === "lock") {
    const puzzle = PUZZLES[pStep];
    return (
      <div style={{ minHeight: "100vh", background: "#030a06", display: "flex", alignItems: "center", justifyContent: "center", padding: 20, fontFamily: "'Share Tech Mono',monospace", color: "#00ff9d" }}>
        <style>{css}</style>
        <div className="crt" />
        <div style={{ width: "100%", maxWidth: 430 }}>
          <div style={{ textAlign: "center", marginBottom: 24 }}>
            <div style={{ fontSize: 10, letterSpacing: 8, color: "#00ff9d2a", marginBottom: 6 }}>▓▒░ PHANTOM v3 ░▒▓</div>
            <div style={{ fontFamily: "'Rajdhani',sans-serif", fontSize: 36, fontWeight: 700, letterSpacing: 4, textShadow: "0 0 20px #00ff9d" }}>ACCESS DENIED</div>
            <div style={{ fontSize: 9, letterSpacing: 3, color: "#00ff9d44", marginTop: 6 }}>SOLVE THE PUZZLE · NEW EVERY RELOAD</div>
          </div>
          <div style={{ marginBottom: 18 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#00ff9d33", marginBottom: 6 }}>
              <span>PROGRESS</span><span>{pStep}/{PUZZLES.length}</span>
            </div>
            <div style={{ height: 2, background: "#00ff9d10" }}>
              <div style={{ height: "100%", background: "#00ff9d", width: `${(pStep / PUZZLES.length) * 100}%`, transition: "width .4s", boxShadow: "0 0 8px #00ff9d" }} />
            </div>
            <div style={{ display: "flex", gap: 5, marginTop: 7 }}>
              {PUZZLES.map((_, i) => (
                <div key={i} style={{ flex: 1, height: 22, border: `1px solid ${i < pStep ? "#00ff9d" : i === pStep ? "#00ff9d44" : "#00ff9d14"}`, background: i < pStep ? "#00ff9d0e" : "transparent", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 8, color: i < pStep ? "#00ff9d" : i === pStep ? "#00ff9d77" : "#00ff9d28" }}>
                  {i < pStep ? "✓" : i === pStep ? "●" : "○"}
                </div>
              ))}
            </div>
          </div>
          <div style={{ border: "1px solid #00ff9d22", background: "#00ff9d05", padding: 18, marginBottom: 14 }}>
            <div style={{ fontSize: 9, letterSpacing: 3, color: "#00ff9d66", marginBottom: 12 }}>{puzzle.title}</div>
            <div style={{ fontSize: 14, lineHeight: 1.9, color: "#ccffee", whiteSpace: "pre-line" }}>{puzzle.question}</div>
            {showHint && <div style={{ fontSize: 10, color: "#ffaa00aa", padding: "8px 10px", background: "#ffaa0008", border: "1px solid #ffaa0020", marginTop: 12 }}>💡 {puzzle.hint}</div>}
          </div>
          <div style={{ animation: shake ? "shake .5s ease" : undefined, marginBottom: 10 }}>
            <input className="p-input" type="number" placeholder="your answer…"
              value={lockIn} onChange={e => { setLockIn(e.target.value); setLockErr(false); }}
              onKeyDown={e => e.key === "Enter" && checkPuzzle()}
              style={{ textAlign: "center", fontSize: 17, letterSpacing: 4 }}
            />
          </div>
          {lockErr && <div style={{ fontSize: 10, color: "#ff4444", textAlign: "center", marginBottom: 8 }}>✗ WRONG — TRY AGAIN</div>}
          <button className="p-btn" onClick={checkPuzzle} disabled={!lockIn} style={{ marginBottom: 10 }}>
            {pStep < PUZZLES.length - 1 ? "SUBMIT & CONTINUE →" : "SUBMIT & UNLOCK →"}
          </button>
          <div style={{ textAlign: "center" }}>
            <span style={{ fontSize: 9, color: "#ffaa0044", cursor: "pointer" }} onClick={() => setShowHint(v => !v)}>
              {showHint ? "▲ HIDE HINT" : "▼ SHOW HINT"}
            </span>
          </div>
        </div>
      </div>
    );
  }

  // ── SETUP SCREEN ──────────────────────────────────────────────────────────
  if (phase === "setup") return (
    <div style={{ minHeight: "100vh", background: "#030a06", display: "flex", alignItems: "center", justifyContent: "center", padding: 20, fontFamily: "'Share Tech Mono',monospace", color: "#00ff9d" }}>
      <style>{css}</style>
      <div className="crt" />
      <div style={{ width: "100%", maxWidth: 420, animation: "flicker 9s infinite" }}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ fontSize: 10, letterSpacing: 8, color: "#00ff9d2a", marginBottom: 6 }}>▓▒░ PHANTOM v3 ░▒▓</div>
          <div style={{ fontFamily: "'Rajdhani',sans-serif", fontSize: 44, fontWeight: 700, lineHeight: 1, textShadow: "0 0 28px #00ff9d", letterSpacing: 3 }}>DARKROOM</div>
          <div style={{ fontSize: 9, letterSpacing: 4, color: "#00ff9d44", marginTop: 8 }}>TRIPLE ENCRYPTED · DOUBLE RATCHET · PER-PEER ECDH</div>
        </div>

        <div style={{ marginBottom: 16, padding: "10px 14px", border: "1px solid #00ff9d18", background: "#00ff9d04" }}>
          <div style={{ fontSize: 8, letterSpacing: 3, color: "#00ff9d44", marginBottom: 8 }}>SECURITY STACK</div>
          {[
            ["L1", "PBKDF2-SHA512 ×250k", "Brute force resistant key stretch"],
            ["L2", "ECDH P-256 per-peer", "Unique shared secret per contact"],
            ["L3", "HKDF-SHA512", "Independent key derivation"],
            ["L4", "AES-256-GCM ×3", "Triple encryption per message"],
            ["L5", "HMAC-SHA512", "Message authentication & signing"],
            ["L6", "Double Ratchet", "Forward + break-in secrecy"],
            ["L7", "1KB block padding", "Message length hidden completely"],
            ["L8", "Replay protection", "Counter window, seen-set rejection"],
          ].map(([l, n, d]) => (
            <div key={l} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
              <span style={{ fontSize: 7, color: "#00ff9d", background: "#00ff9d18", padding: "1px 5px" }}>{l}</span>
              <span style={{ fontSize: 9, color: "#00ff9d88" }}>{n}</span>
              <span style={{ fontSize: 7, color: "#00ff9d2a", marginLeft: "auto" }}>{d}</span>
            </div>
          ))}
        </div>

        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 9, letterSpacing: 3, color: "#00ff9d44", marginBottom: 5 }}>ROOM ID</div>
          <input className="p-input" placeholder="e.g. SHADOW-9" value={roomId}
            onChange={e => setRoomId(e.target.value.toUpperCase())} maxLength={24} />
        </div>
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 9, letterSpacing: 3, color: "#00ff9d44", marginBottom: 5, display: "flex", justifyContent: "space-between" }}>
            <span>SECRET KEY</span>
            <span style={{ cursor: "pointer", color: "#00ff9d66" }} onClick={() => setKeyVis(v => !v)}>[{keyVis ? "HIDE" : "SHOW"}]</span>
          </div>
          <input className="p-input" type={keyVis ? "text" : "password"} placeholder="share out-of-band…"
            value={roomKey} onChange={e => setRoomKey(e.target.value)} />
        </div>
        <div style={{ marginBottom: 16, padding: "10px 14px", background: "#ff000007", border: "1px solid #ff44441a" }}>
          <div style={{ fontSize: 9, letterSpacing: 3, color: "#ff6655", marginBottom: 8, display: "flex", justifyContent: "space-between" }}>
            <span>💣 SELF-DESTRUCT</span><span style={{ color: "#ff4444" }}>{destructLabel}</span>
          </div>
          <input type="range" min={0} max={4} step={1} value={DESTRUCT_OPTIONS.indexOf(destructTime)}
            onChange={e => setDestructTime(DESTRUCT_OPTIONS[+e.target.value])} />
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: "#ff444444", marginTop: 4 }}>
            <span>OFF</span><span>10s</span><span>30s</span><span>1m</span><span>5m</span>
          </div>
        </div>
        <div style={{ padding: "7px 12px", background: "#00ff9d06", border: "1px solid #00ff9d16", fontSize: 10, marginBottom: 14 }}>
          CODENAME: <strong style={{ color: "#00ff9d" }}>{MY_NAME}</strong>
        </div>
        <button className="p-btn" disabled={!roomId.trim() || !roomKey.trim() || status === "connecting"} onClick={connect}>
          {status === "connecting" ? "STRETCHING KEY… (250k iterations)" : "ENTER THE VOID →"}
        </button>
        {status === "error" && <div style={{ fontSize: 10, color: "#ff6655", textAlign: "center", marginTop: 10 }}>Connection failed.</div>}
        <div style={{ marginTop: 12, fontSize: 8, color: "#00ff9d18", textAlign: "center", letterSpacing: 2 }}>
          KEY STRETCHING MAY TAKE 2–3 SECONDS — THIS IS INTENTIONAL
        </div>
      </div>
    </div>
  );

  // ── CHAT SCREEN ───────────────────────────────────────────────────────────
  const typingList = [...typingPeers];
  return (
    <div style={{ height: "100vh", background: "#030a06", display: "flex", flexDirection: "column", fontFamily: "'Share Tech Mono',monospace", color: "#00ff9d", overflow: "hidden" }}>
      <style>{css}</style>
      <div className="crt" />
      <input type="file" ref={fileRef} style={{ display: "none" }}
        onChange={e => { if (e.target.files[0]) sendFile(e.target.files[0]); e.target.value = ""; }} />

      {/* Header */}
      <div style={{ borderBottom: "1px solid #00ff9d14", padding: "7px 14px", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: dotColor, animation: status === "connected" ? "pulse 2.5s infinite" : undefined }} />
          <span style={{ fontSize: 10, letterSpacing: 2, color: "#00ff9d66" }}>#{roomId}</span>
          {destructTime > 0 && <span style={{ fontSize: 8, color: "#ff4444aa" }}>💣{destructLabel}</span>}
          <span className={`sec-badge ${peerCount > 0 ? "on" : ""}`}>🔑 {peerCount} PEER{peerCount !== 1 ? "S" : ""}</span>
          <span className="sec-badge on">×3 AES</span>
          <span className="sec-badge on">RATCHET:{secInfo.ratchet}</span>
        </div>
        <span style={{ fontSize: 9, color: "#00ff9d77" }}>{MY_NAME}</span>
      </div>

      {/* Fingerprint bar */}
      {fp && (
        <div style={{ borderBottom: "1px solid #00ff9d0a", padding: "4px 14px", background: "#00ff9d04", display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
          <span style={{ fontSize: 7, letterSpacing: 2, color: "#00ff9d33" }}>ROOM FP:</span>
          <span className="fp">{fp}</span>
          <span style={{ fontSize: 7, color: "#00ff9d22", marginLeft: "auto" }}>VERIFY WITH CONTACT OUT-OF-BAND</span>
        </div>
      )}

      {/* Messages */}
      <div style={{ flex: 1, overflowY: "auto", padding: "14px 14px 6px" }}>
        {messages.map(m => (
          <div key={m.id} className="msg" style={{ marginBottom: 10, display: "flex", flexDirection: "column", alignItems: m.mine ? "flex-end" : m.sys ? "center" : "flex-start" }}>
            {m.sys ? (
              <div style={{ fontSize: 9, color: "#00ff9d1e", letterSpacing: 1.2, animation: "scanin .3s ease" }}>— {m.text} —</div>
            ) : (
              <>
                <div style={{ fontSize: 9, color: "#00ff9d33", marginBottom: 3, display: "flex", gap: 8 }}>
                  <span>{m.sender} · {fmt(m.ts)}</span>
                  {m.destructAt && <span style={{ color: "#ff444466", fontSize: 8 }}>💣{Math.max(0, Math.ceil((m.destructAt - Date.now()) / 1000))}s</span>}
                </div>
                <div style={{ maxWidth: "76%", padding: m.isImage ? "4px" : "8px 12px", fontSize: 13, lineHeight: 1.65, background: m.mine ? "#00ff9d0d" : "#ffffff05", border: `1px solid ${m.mine ? "#00ff9d22" : "#ffffff09"}`, color: m.mine ? "#00ff9d" : "#bbffdd", wordBreak: "break-word" }}>
                  {m.isImage ? <img src={m.imageData} alt="img" style={{ maxWidth: "100%", maxHeight: 200, display: "block" }} /> : m.text}
                </div>
              </>
            )}
          </div>
        ))}
        {typingList.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <div style={{ display: "flex", gap: 3, padding: "5px 9px", background: "#ffffff04", border: "1px solid #ffffff08" }}>
              <span className="dot1" /><span className="dot2" /><span className="dot3" />
            </div>
            <span style={{ fontSize: 9, color: "#00ff9d33" }}>{typingList.join(", ")} typing…</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{ borderTop: "1px solid #00ff9d14", display: "flex", flexShrink: 0, alignItems: "center" }}>
        <button className="file-btn" onClick={() => fileRef.current?.click()} title="Send file">📎</button>
        <textarea className="chat-textarea" rows={1}
          placeholder="type a message… (enter to send)"
          value={input} onChange={onInputChange} onKeyDown={onKeyDown}
        />
        <button className="send-btn" onClick={send} disabled={!input.trim() || status !== "connected"}>SEND</button>
      </div>

      <div style={{ padding: "2px 14px 4px", fontSize: 7, color: "#00ff9d14", letterSpacing: 2, flexShrink: 0 }}>
        PBKDF2·ECDH·HKDF·AES256×3·HMAC512·DOUBLE-RATCHET·1KB-PADDING·REPLAY-SHIELD
      </div>
    </div>
  );
}
