/*
 * Cross-platform dev runner: starts the standalone relay (its own process/port)
 * alongside the Vite dev server, so `npm run dev` is still a single command.
 * Both are cleaned up on Ctrl-C.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));
const mode = process.argv[2] || "dev"; // "dev" or "preview"
const children = [];

function run(args, label) {
  const p = spawn(process.execPath, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  p.stdout.on("data", (d) => process.stdout.write(d));
  p.stderr.on("data", (d) => process.stderr.write(d));
  p.on("exit", (code) => {
    if (code !== null && code !== 0) console.error(`[dev] ${label} exited with code ${code}`);
  });
  children.push(p);
  return p;
}

run(["relay-server.mjs"], "relay");
const viteArgs =
  mode === "preview"
    ? [join(root, "node_modules", "vite", "bin", "vite.js"), "preview"]
    : [join(root, "node_modules", "vite", "bin", "vite.js")];
run(viteArgs, "vite");

function shutdown() {
  for (const c of children) {
    try {
      c.kill();
    } catch {
      /* ignore */
    }
  }
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);