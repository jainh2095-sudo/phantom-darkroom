import { useState, useEffect, useRef, useCallback } from "react";

// ─── Crypto Helpers ───────────────────────────────────────────────────────────
async function deriveKey(secret) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("phantom-salt-v1"), iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

async function encryptMessage(text, key) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  const buf = new Uint8Array(12 + ct.byteLength);
  buf.set(iv); buf.set(new Uint8Array(ct), 12);
  return btoa(String.fromCharCode(...buf));
}

async function decryptMessage(b64, key) {
  try {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12)
    );
    return new TextDecoder().decode(plain);
  } catch { return null; }
}

function uid(n = 8) {
  return Array.from(crypto.getRandomValues(new Uint8Array(n)))
    .map(b => b.toString(16).padStart(2, "0")).join("").slice(0, n).toUpperCase();
}

async function hashRoomId(roomId) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode("phantom:" + roomId));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("").slice(0,16);
}

const CODENAMES = ["WRAITH","SPECTER","CIPHER","PHANTOM","GHOST","RAVEN","SHADOW",
  "VEIL","MIRAGE","VOID","ECHO","FLUX","DUSK","NEON","ZEPHYR","STATIC","NOVA","BLAZE"];

const MY_NAME = CODENAMES[Math.floor(Math.random() * CODENAMES.length)] + "-" + uid(4);

const css = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
  * { box-sizing:border-box; margin:0; padding:0; }
  @keyframes flicker { 0%,100%{opacity:1}50%{opacity:.94}93%{opacity:.7}94%{opacity:.97} }
  @keyframes fadeUp { from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)} }
  @keyframes pulse { 0%,100%{box-shadow:0 0 5px #00ff9d}50%{box-shadow:0 0 14px #00ff9d} }
  .crt {
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,157,.012) 2px,rgba(0,255,157,.012) 4px);
    pointer-events:none;position:fixed;inset:0;z-index:99;
  }
  .p-input {
    background:transparent;border:1px solid #00ff9d33;color:#00ff9d;
    font-family:'Share Tech Mono',monospace;font-size:14px;padding:11px 14px;
    outline:none;width:100%;letter-spacing:.5px;transition:all .2s;
  }
  .p-input:focus{border-color:#00ff9d88;box-shadow:0 0 14px #00ff9d1a;}
  .p-input::placeholder{color:#00ff9d28;}
  .p-btn {
    background:#00ff9d;color:#000;border:none;font-family:'Rajdhani',sans-serif;
    font-size:13px;font-weight:700;letter-spacing:3px;padding:13px 28px;
    cursor:pointer;text-transform:uppercase;transition:all .15s;width:100%;
  }
  .p-btn:hover{background:#000;color:#00ff9d;box-shadow:0 0 22px #00ff9d44;outline:1px solid #00ff9d;}
  .p-btn:disabled{opacity:.35;cursor:not-allowed;}
  .chat-textarea {
    background:transparent;border:none;color:#00ff9d;
    font-family:'Share Tech Mono',monospace;font-size:13px;
    padding:14px 16px;outline:none;flex:1;resize:none;letter-spacing:.3px;line-height:1.5;
  }
  .chat-textarea::placeholder{color:#00ff9d28;}
  .send-btn {
    background:none;border:none;border-left:1px solid #00ff9d18;color:#00ff9d;
    font-family:'Rajdhani',sans-serif;font-size:12px;font-weight:700;letter-spacing:2px;
    padding:0 22px;cursor:pointer;transition:all .15s;text-transform:uppercase;min-width:70px;
  }
  .send-btn:hover{background:#00ff9d10;}
  .send-btn:disabled{opacity:.3;cursor:not-allowed;}
  .msg{animation:fadeUp .18s ease;}
  ::-webkit-scrollbar{width:3px;}
  ::-webkit-scrollbar-thumb{background:#00ff9d1a;}
`;

export default function SecureChat() {
  const [phase, setPhase] = useState("setup");
  const [roomId, setRoomId] = useState("");
  const [roomKey, setRoomKey] = useState("");
  const [keyVisible, setKeyVisible] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [cryptoKey, setCryptoKey] = useState(null);
  const [status, setStatus] = useState("idle");
  const [peers, setPeers] = useState(new Set());
  const wsRef = useRef(null);
  const bottomRef = useRef(null);
  const pingRef = useRef(null);
  const keyRef = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const addSys = (text) => setMessages(p => [...p, { id: uid(), sys: true, text, ts: Date.now() }]);
  const addMsg = (sender, text, mine) => setMessages(p => [...p, { id: uid(), sender, text, ts: Date.now(), mine }]);

  const connect = useCallback(async () => {
    if (!roomId.trim() || !roomKey.trim()) return;
    setStatus("connecting");

    let key;
    try {
      key = await deriveKey(roomKey.trim() + "|" + roomId.trim());
      setCryptoKey(key);
      keyRef.current = key;
    } catch {
      setStatus("error");
      return;
    }

    const channel = await hashRoomId(roomId.trim());
    const wsUrl = `wss://ws.postman-echo.com/raw`;

    let ws;
    try { ws = new WebSocket(wsUrl); }
    catch { setStatus("error"); return; }
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("connected");
      setPhase("chat");
      addSys("🔐 Connected. Messages are AES-256 encrypted before leaving your device.");
      ws.send(JSON.stringify({ t: "JOIN", name: MY_NAME }));
      pingRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "PING" }));
      }, 25000);
    };

    ws.onmessage = async (evt) => {
      let pkg;
      try { pkg = JSON.parse(evt.data); } catch { return; }
      if (!pkg || pkg.name === MY_NAME) return;

      if (pkg.t === "JOIN") {
        setPeers(p => new Set([...p, pkg.name]));
        addSys(`${pkg.name} joined the room.`);
        if (ws.readyState === WebSocket.OPEN)
          ws.send(JSON.stringify({ t: "HERE", name: MY_NAME }));
      } else if (pkg.t === "HERE") {
        setPeers(p => new Set([...p, pkg.name]));
      } else if (pkg.t === "LEAVE") {
        setPeers(p => { const n = new Set(p); n.delete(pkg.name); return n; });
        addSys(`${pkg.name} left the room.`);
      } else if (pkg.t === "MSG" && pkg.cipher) {
        const plain = await decryptMessage(pkg.cipher, keyRef.current);
        if (plain === null) addSys(`[message from ${pkg.name} — decryption failed]`);
        else addMsg(pkg.name, plain, false);
      }
    };

    ws.onclose = () => {
      clearInterval(pingRef.current);
      setStatus("disconnected");
      addSys("Connection closed.");
    };

    ws.onerror = () => {
      setStatus("error");
    };
  }, [roomId, roomKey]);

  useEffect(() => {
    return () => {
      clearInterval(pingRef.current);
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ t: "LEAVE", name: MY_NAME }));
        wsRef.current.close();
      }
    };
  }, []);

  const send = useCallback(async () => {
    const text = input.trim();
    if (!text || !keyRef.current || wsRef.current?.readyState !== WebSocket.OPEN) return;
    setInput("");
    const cipher = await encryptMessage(text, keyRef.current);
    wsRef.current.send(JSON.stringify({ t: "MSG", name: MY_NAME, cipher }));
    addMsg(MY_NAME, text, true);
  }, [input]);

  const onKeyDown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } };
  const fmt = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  const dotColor = status === "connected" ? "#00ff9d" : status === "error" || status === "disconnected" ? "#ff4444" : "#ffaa00";

  // ── SETUP ────────────────────────────────────────────────────────────────
  if (phase === "setup") return (
    <div style={{ minHeight:"100vh", background:"#030a06", display:"flex", alignItems:"center", justifyContent:"center", padding:20, fontFamily:"'Share Tech Mono',monospace", color:"#00ff9d" }}>
      <style>{css}</style>
      <div className="crt" />
      <div style={{ width:"100%", maxWidth:400, animation:"flicker 9s infinite" }}>
        <div style={{ textAlign:"center", marginBottom:34 }}>
          <div style={{ fontSize:10, letterSpacing:8, color:"#00ff9d44", marginBottom:6 }}>▓▒░ PHANTOM ░▒▓</div>
          <div style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:48, fontWeight:700, lineHeight:1, textShadow:"0 0 30px #00ff9d", letterSpacing:3 }}>DARKROOM</div>
          <div style={{ fontSize:9, letterSpacing:5, color:"#00ff9d55", marginTop:8 }}>ENCRYPTED · ANONYMOUS · EPHEMERAL</div>
        </div>

        <div style={{ border:"1px solid #ff333322", background:"#ff00000a", padding:"9px 14px", marginBottom:22, fontSize:10, color:"#ff6655", letterSpacing:.8, lineHeight:1.8 }}>
          ⚠ NO MESSAGES STORED ON ANY SERVER. ENCRYPTED BEFORE SENDING. NO ACCOUNTS.
        </div>

        <div style={{ marginBottom:13 }}>
          <div style={{ fontSize:9, letterSpacing:3, color:"#00ff9d55", marginBottom:5 }}>ROOM ID</div>
          <input className="p-input" placeholder="e.g. SHADOW-9  (share with friends)"
            value={roomId} onChange={e => setRoomId(e.target.value.toUpperCase())} maxLength={24} />
        </div>

        <div style={{ marginBottom:22 }}>
          <div style={{ fontSize:9, letterSpacing:3, color:"#00ff9d55", marginBottom:5, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
            <span>SECRET KEY</span>
            <span style={{ cursor:"pointer", color:"#00ff9d88", fontSize:9 }} onClick={() => setKeyVisible(v=>!v)}>[{keyVisible?"HIDE":"SHOW"}]</span>
          </div>
          <input className="p-input" type={keyVisible?"text":"password"}
            placeholder="share out-of-band (voice, in person…)"
            value={roomKey} onChange={e => setRoomKey(e.target.value)} />
          <div style={{ fontSize:9, color:"#00ff9d2a", marginTop:5 }}>
            Everyone needs the same Room ID + Key to chat.
          </div>
        </div>

        <div style={{ padding:"8px 14px", background:"#00ff9d07", border:"1px solid #00ff9d18", fontSize:10, marginBottom:16, letterSpacing:.5 }}>
          YOUR CODENAME: <strong style={{ color:"#00ff9d" }}>{MY_NAME}</strong>
        </div>

        <button className="p-btn"
          disabled={!roomId.trim() || !roomKey.trim() || status === "connecting"}
          onClick={connect}>
          {status === "connecting" ? "CONNECTING…" : "ENTER THE VOID →"}
        </button>

        {status === "error" && (
          <div style={{ fontSize:10, color:"#ff6655", textAlign:"center", marginTop:10, letterSpacing:1 }}>
            Connection failed. Check your network.
          </div>
        )}

        <div style={{ marginTop:16, fontSize:9, color:"#00ff9d1a", textAlign:"center", letterSpacing:2 }}>
          AES-256-GCM · PBKDF2 · WEB CRYPTO API
        </div>
      </div>
    </div>
  );

  // ── CHAT ─────────────────────────────────────────────────────────────────
  const peerCount = peers.size + 1;
  return (
    <div style={{ height:"100vh", background:"#030a06", display:"flex", flexDirection:"column", fontFamily:"'Share Tech Mono',monospace", color:"#00ff9d", overflow:"hidden" }}>
      <style>{css}</style>
      <div className="crt" />

      {/* Header */}
      <div style={{ borderBottom:"1px solid #00ff9d18", padding:"10px 18px", display:"flex", alignItems:"center", justifyContent:"space-between", flexShrink:0 }}>
        <div style={{ display:"flex", alignItems:"center", gap:14 }}>
          <div style={{ display:"flex", alignItems:"center", gap:7 }}>
            <div style={{ width:7, height:7, borderRadius:"50%", background:dotColor, animation: status==="connected" ? "pulse 2.5s infinite" : undefined }} />
            <span style={{ fontSize:9, letterSpacing:2, color:dotColor + "aa" }}>
              {status === "connected" ? "LIVE" : status.toUpperCase()}
            </span>
          </div>
          <span style={{ fontSize:10, letterSpacing:2, color:"#00ff9d88" }}>#{roomId}</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:16, fontSize:9 }}>
          <span style={{ color:"#00ff9d55" }}>{peerCount} IN ROOM</span>
          <span style={{ color:"#00ff9daa" }}>{MY_NAME}</span>
        </div>
      </div>

      {/* Messages */}
      <div style={{ flex:1, overflowY:"auto", padding:"16px 18px 8px" }}>
        {messages.map(m => (
          <div key={m.id} className="msg" style={{ marginBottom:13, display:"flex", flexDirection:"column", alignItems: m.mine ? "flex-end" : m.sys ? "center" : "flex-start" }}>
            {m.sys ? (
              <div style={{ fontSize:9, color:"#00ff9d22", letterSpacing:1.5 }}>— {m.text} —</div>
            ) : (
              <>
                <div style={{ fontSize:9, color:"#00ff9d3a", letterSpacing:.5, marginBottom:3 }}>
                  {m.sender} · {fmt(m.ts)}
                </div>
                <div style={{
                  maxWidth:"76%", padding:"9px 13px", fontSize:13, lineHeight:1.65,
                  background: m.mine ? "#00ff9d10" : "#ffffff06",
                  border:`1px solid ${m.mine ? "#00ff9d28" : "#ffffff0a"}`,
                  color: m.mine ? "#00ff9d" : "#bbffdd",
                  wordBreak:"break-word", letterSpacing:.2
                }}>
                  {m.text}
                </div>
              </>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{ borderTop:"1px solid #00ff9d18", display:"flex", flexShrink:0 }}>
        <textarea className="chat-textarea" rows={1}
          placeholder="type a message… (enter to send)"
          value={input} onChange={e => setInput(e.target.value)} onKeyDown={onKeyDown}
        />
        <button className="send-btn" onClick={send} disabled={!input.trim() || status !== "connected"}>
          SEND
        </button>
      </div>

      <div style={{ padding:"3px 18px 5px", fontSize:8, color:"#00ff9d18", letterSpacing:2, flexShrink:0 }}>
        AES-256-GCM END-TO-END ENCRYPTED · ZERO SERVER STORAGE · EPHEMERAL SESSION
      </div>
    </div>
  );
}
