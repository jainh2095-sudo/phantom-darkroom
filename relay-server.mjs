/*
 * Phantom Darkroom — standalone relay.
 *
 * A dumb, in-memory broadcast relay that runs as its OWN process on its OWN
 * port (default 8787), so it is a different origin / trust domain from the
 * page host. It never sees plaintext: it only forwards the ciphertext packets
 * the clients send (padded to fixed size, with decoy traffic mixed in).
 *
 * Privacy by construction:
 *   - ZERO logging — it never records a connection, an IP, a time, or a packet.
 *   - No persistence — state is a per-channel in-memory set; gone on exit.
 *   - No metadata — it only groups sockets by the FIRST path segment (the room
 *     hash) and echoes bytes to the rest of the room.
 *
 * NOTE: this cannot hide the client's source IP from the relay at the TCP
 * layer. For real IP anonymity route through Tor; see README.
 */
import { createServer } from "node:http";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || "127.0.0.1";

const wss = new WebSocketServer({ noServer: true });
const channels = new Map(); // channel -> Set<ws>

const server = createServer();

server.on("upgrade", (req, socket, head) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch {
    socket.destroy();
    return;
  }
  const m = /^\/relay\/([^/]+)\/?/.exec(pathname);
  if (!m) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    const channel = m[1];
    let room = channels.get(channel);
    if (!room) {
      room = new Set();
      channels.set(channel, room);
    }
    room.add(ws);
    ws.on("message", (data) => {
      for (const other of room) {
        if (other !== ws && other.readyState === other.OPEN) {
          // Always a text frame so the receiving browser gets a string, not a Blob.
          other.send(data, { binary: false });
        }
      }
    });
    ws.on("close", () => {
      room.delete(ws);
      if (room.size === 0) channels.delete(channel);
    });
    ws.on("error", () => {});
  });
});

server.listen(PORT, HOST, () => {
  // No per-connection logging — only a one-time readiness line.
  console.log(`[relay] listening on ${HOST}:${PORT} (no logs, no persistence)`);
});