// SPDX-License-Identifier: Apache-2.0 OR MIT

// Test harness that boots the pinned reference Hysteria 2 server (installed via
// `mise` as `hysteria`, §3.8) for conformance tests, mirroring how pframes-rs'
// `parquet-server.mjs` is driven from Rust:
//
//   - the caller passes a partial Hysteria 2 *server* config (JSON);
//   - we generate a self-signed `localhost` cert, inject TLS + a listen port,
//     run `hysteria server`, and wait until it is up;
//   - the matching *client* config (a ready-to-parse `hysteria2://` URI plus the
//     structured fields and the cert pin) is printed as the single line on
//     stdout, which the Rust test reads; the server's own logs go to stderr.
//
// Shut down by sending SIGTERM/SIGINT, or — when stdin is a pipe — by closing
// it (the Rust harness keeps stdin open for the server's lifetime and closes it
// to request a graceful stop). Either way the child server is terminated and
// the temporary cert/config directory is removed.

import { type ChildProcess, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createSocket } from "node:dgram";
import { fstatSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { createInterface } from "node:readline";
import { parseArgs as parseCliArgs } from "node:util";
import { generate } from "selfsigned";
import { ensureError, runScript } from "./helpers/run-script.ts";

/** Log line printed by the server once it is accepting connections. */
const READY_MARKER = "server up and running";
/** How long to wait for that line before giving up. */
const STARTUP_TIMEOUT_MS = 15_000;
/**
 * Startup attempts before giving up. `hysteria server` binds the listen port
 * itself, so there is an unavoidable gap between us choosing a free port and it
 * claiming it; under the parallel test suite another server can take that port
 * in the gap, making hysteria exit before startup. Each retry picks a fresh
 * port.
 */
const MAX_START_ATTEMPTS = 5;
/** Host advertised to the client (the cert covers `localhost` / loopback). */
const HOST = "127.0.0.1";
const SNI = "localhost";

/** Salamander obfuscation, as carried by a `hysteria2://` link. */
interface ClientObfs {
  type: "salamander";
  password: string;
}

/**
 * Connection info handed back to the Rust test as the first stdout line.
 * Mirror of `HysteriaClientConfig` in `crates/hysteria/tests/common/mod.rs` —
 * keep the two field sets in sync (there is no shared schema across languages).
 */
interface ClientConfig {
  /** Ready-to-parse `hysteria2://` URI. */
  url: string;
  /** `host:port` of the server. */
  server: string;
  port: number;
  /** Bearer auth password. */
  auth: string;
  /** TLS server name (the cert's CN/SAN). */
  sni: string;
  /** Path to the self-signed cert (PEM), trusted via the CA path since the cert
   * is not publicly rooted. */
  caCertPath: string;
  /** Present only when the server config enables obfuscation. */
  obfs: ClientObfs | null;
}

/** Minimal view of the Hysteria 2 server config we read back from the caller. */
interface ServerConfig {
  listen?: string;
  tls?: { cert: string; key: string };
  auth?: { type?: string; password?: string };
  obfs?: { type?: string; salamander?: { password?: string } };
  [key: string]: unknown;
}

/** Parse the caller-provided partial server config from `--config` (empty when omitted). */
function parseServerConfig(argv: string[]): ServerConfig {
  // `parseCliArgs` (node:util) handles `--config value` / `--config=value` and,
  // in its default strict mode, rejects unknown flags and stray positionals.
  const { values } = parseCliArgs({ args: argv, options: { config: { type: "string" } } });
  const json = values.config;
  if (json === undefined || json.trim() === "") {
    return {};
  }
  return JSON.parse(json) as ServerConfig;
}

/** Reserve a free UDP port by binding the ephemeral range, then releasing it. */
async function pickFreePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const socket = createSocket("udp4");
    socket.once("error", (err) => {
      socket.close();
      reject(err);
    });
    socket.bind(0, HOST, () => {
      const { port } = socket.address();
      socket.close(() => resolve(port));
    });
  });
}

/** Generate a self-signed cert/key pair valid for `localhost` and loopback. */
async function generateCertificate(): Promise<{ cert: string; key: string }> {
  const result = await generate([{ name: "commonName", value: SNI }], {
    keySize: 2048,
    algorithm: "sha256",
    extensions: [
      {
        name: "subjectAltName",
        altNames: [
          { type: 2, value: SNI }, // DNS
          { type: 7, ip: "127.0.0.1" }, // IPv4
          { type: 7, ip: "::1" }, // IPv6
        ],
      },
    ],
  });
  return { cert: result.cert, key: result.private };
}

/**
 * Create a temp dir and write cert/key/config into it, returning the effective
 * config (for deriving the client config), the config path (to spawn against),
 * and a one-shot cleanup that removes the dir.
 */
async function writeServerFiles({
  provided,
  port,
  cert,
  key,
}: {
  provided: ServerConfig;
  port: number;
  cert: string;
  key: string;
}): Promise<{
  config: ServerConfig;
  configPath: string;
  certPath: string;
  cleanup: () => Promise<void>;
}> {
  const workDir = await mkdtemp(join(tmpdir(), "hysteria-server-"));
  const certPath = join(workDir, "cert.pem");
  const keyPath = join(workDir, "key.pem");
  const configPath = join(workDir, "config.json");

  // Force our TLS + listen address; keep the rest of the caller's config,
  // defaulting auth to a random password when unset.
  const config: ServerConfig = {
    ...provided,
    listen: `:${port}`,
    tls: { cert: certPath, key: keyPath },
    auth: provided.auth ?? { type: "password", password: randomUUID() },
  };

  await writeFile(certPath, cert);
  await writeFile(keyPath, key);
  await writeFile(configPath, JSON.stringify(config));

  const cleanup = (): Promise<void> => rm(workDir, { recursive: true, force: true });

  return { config, configPath, certPath, cleanup };
}

/** Derive the client config from the effective server config and cert path. */
function deriveClientConfig({
  config,
  port,
  certPath,
}: {
  config: ServerConfig;
  port: number;
  certPath: string;
}): ClientConfig {
  const auth = config.auth?.password ?? "";

  const obfs: ClientObfs | null =
    config.obfs?.type === "salamander"
      ? { type: "salamander", password: config.obfs.salamander?.password ?? "" }
      : null;

  const params = new URLSearchParams({ sni: SNI });
  if (obfs !== null) {
    params.set("obfs", "salamander");
    params.set("obfs-password", obfs.password);
  }
  const url = `hysteria2://${encodeURIComponent(auth)}@${HOST}:${port}/?${params.toString()}`;

  return {
    url,
    server: `${HOST}:${port}`,
    port,
    auth,
    sni: SNI,
    caCertPath: certPath,
    obfs,
  };
}

/**
 * Wire every shutdown trigger to gracefully stop the server. Triggers:
 * SIGINT/SIGTERM; a controlling parent closing our stdin (a pipe/socket — not a
 * TTY, file, or `/dev/null`, so interactive / `mise run` use is unaffected and
 * falls back to signals); the config consumer closing our stdout (EPIPE); and a
 * SIGKILL backstop if we exit abruptly. SIGTERM escalates to SIGKILL so a stuck
 * server can't hang us.
 */
function wireShutdown(child: ChildProcess): void {
  const shutdown = (): void => {
    child.kill("SIGTERM");
    setTimeout(() => child.kill("SIGKILL"), 2_000).unref();
  };
  process.on("exit", () => child.kill("SIGKILL"));
  process.on("SIGINT", shutdown).on("SIGTERM", shutdown);
  process.stdout.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EPIPE") shutdown();
  });
  const stdinStat = fstatSync(0);
  if (stdinStat.isFIFO() || stdinStat.isSocket()) {
    process.stdin.once("end", shutdown).resume();
  }
}

/** A server that has logged {@link READY_MARKER} and is accepting connections. */
interface StartedServer {
  /** The client config to announce on stdout. */
  clientConfig: ClientConfig;
  /** Resolves with the server's exit code once it exits. */
  exited: Promise<number>;
  /** Removes the temp cert/config directory. */
  cleanup: () => Promise<void>;
}

/**
 * One startup attempt: pick a free port, write the server files, spawn the
 * server, and forward its logs (written to stderr) to our stderr. Resolves with
 * the running server once it logs {@link READY_MARKER}, or `null` if it exited
 * before becoming ready — a transient port-bind race the caller retries with a
 * fresh port. Rejects (after killing the child and cleaning up) only on a
 * startup timeout or spawn error.
 */
async function attemptStart(
  provided: ServerConfig,
  cert: string,
  key: string,
): Promise<StartedServer | null> {
  const port = await pickFreePort();
  const { config, configPath, certPath, cleanup } = await writeServerFiles({
    provided,
    port,
    cert,
    key,
  });
  const clientConfig = deriveClientConfig({ config, port, certPath });

  const child = spawn("hysteria", ["server", "-c", configPath, "--log-level", "info"], {
    stdio: ["ignore", "ignore", "pipe"],
    env: process.env,
  });

  const {
    promise: ready,
    resolve: resolveReady,
    reject: rejectReady,
  } = Promise.withResolvers<boolean>();
  const { promise: exited, resolve: resolveExit } = Promise.withResolvers<number>();
  let isReady = false;

  if (child.stderr !== null) {
    createInterface({ input: child.stderr }).on("line", (line) => {
      console.error(line);
      if (!isReady && line.includes(READY_MARKER)) {
        isReady = true;
        resolveReady(true);
      }
    });
  }

  const timeout = setTimeout(
    () => rejectReady(new Error("timed out waiting for hysteria to start")),
    STARTUP_TIMEOUT_MS,
  );
  child.once("error", (err) => rejectReady(ensureError(err)));
  child.once("exit", (code) => {
    // Logs are already on stderr. An exit before the ready marker is a startup
    // failure (often a port-bind race) the caller retries; after it, this is
    // the server's real exit code.
    if (isReady) resolveExit(code ?? 0);
    else resolveReady(false);
  });

  let started: boolean;
  try {
    started = await ready;
  } catch (err) {
    child.kill("SIGKILL");
    await cleanup();
    throw err;
  } finally {
    clearTimeout(timeout);
  }

  if (!started) {
    await cleanup();
    return null;
  }

  wireShutdown(child);
  return { clientConfig, exited, cleanup };
}

runScript("Hysteria server", async () => {
  const provided = parseServerConfig(process.argv.slice(2));
  const { cert, key } = await generateCertificate();

  // The cert is port-independent, so reuse it across attempts; only the port
  // pick + bind races, and a fresh port sidesteps a collision.
  let started: StartedServer | null = null;
  for (let attempt = 1; attempt <= MAX_START_ATTEMPTS && started === null; attempt += 1) {
    started = await attemptStart(provided, cert, key);
    if (started === null && attempt < MAX_START_ATTEMPTS) {
      console.error(
        `hysteria exited before startup; retrying (attempt ${attempt + 1}/${MAX_START_ATTEMPTS})`,
      );
    }
  }
  if (started === null) {
    throw new Error(`hysteria exited before startup after ${MAX_START_ATTEMPTS} attempts`);
  }

  const { clientConfig, exited, cleanup } = started;
  let exitCode: number;
  try {
    process.stdout.write(`${JSON.stringify(clientConfig)}\n`);
    exitCode = await exited;
  } finally {
    await cleanup();
  }
  process.exit(exitCode);
});
