# Phantom Darkroom

A quantum-hardened, metadata-annihilating chat: Signal X3DH + triple AES-256-GCM,
PBKDF2-SHA512 key stretching, double ratchet, decoy traffic, burn-on-read…
See the security architecture at the top of `src/Securechat.jsx`.

## Running

```bash
npm install
npm run dev      # standalone relay (:8787) + Vite dev server (:5173)
npm run build    # production build
npm run preview  # standalone relay (:8787) + Vite preview (:4173)

# run the relay alone (e.g. on its own host in production)
npm run relay
```

## How chat transport works

`Phantom Darkroom` relays through a **standalone broadcast WebSocket relay**
(`relay-server.mjs`) that runs as its **own process on its own port** — a
different origin / trust domain from the page host. Clients reach it at:

```
ws(s)://<relay-host>:<relay-port>/relay/<room-hash>/<random-suffix>
```

Defaults to `localhost:8787`. Override the relay at build/deploy time:

```bash
VITE_RELAY_HOST=relay.example.com VITE_RELAY_PORT=8787 npm run build
```

The relay groups sockets by the **first path segment** (the room hash), so
each side can pick a different random suffix without splitting the room. It
is deliberately dumb: **no logging of connections or IPs, no persistence**, and
it only ever forwards ciphertext padded to fixed 4 KB packets (with decoy
traffic mixed in). All security lives in the client.

## Connection resilience

- The relay never echoes your own packets back, so inbound silence is normal
  while waiting alone — the app only reconnects when the relay itself is
  unreachable while a peer is known to be live.
- If the WebSocket drops (relay restart, network blip), the app **reconnects
  automatically** every 5s and re-runs X3DH with fresh Signal keys, so session
  security is preserved. Reconnecting stops only on panic wipe, idle lock or
  session expiry.
- Idle auto-lock counts **real input only** (keys, taps, clicks) — passive time
  spent reading or waiting never triggers it. It warns with a visible countdown
  60s before locking (default 5 min).

## Privacy & anonymity limits (read this)

- The relay **cannot read messages**: content, room key and private keys stay
  in the browser; only triple-AES-256-GCM ciphertext crosses the wire.
- The relay **does** see the source IP of each connection and packet arrival
  timing — that is inherent to any server you connect to and cannot be hidden
  by client-side code. The app's 4 KB padding, exponential jitter and decoy
  traffic make it harder to correlate, but do not eliminate it.
- For **real IP anonymity, route through Tor** (the app is designed to run in
  Tor Browser). Only then is the relay unable to link traffic to your IP.
- Separating the relay from the page host means the page host is no longer the
  relay operator. If the page host itself were malicious it could still serve
  modified JS; the app's page-integrity monitor and the out-of-band SAS code
  are the defenses against that.

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
