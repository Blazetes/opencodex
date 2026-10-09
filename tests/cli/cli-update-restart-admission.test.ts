import { afterEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertUpdateRestartHome, readUpdateRestartHome, type UpdateRestartHomeDeps } from "../../src/cli/update-restart-home";
import { admitUpdateRestartChild, UPDATE_RESTART_CHILD_ENV } from "../../src/cli/update-restart-child";
import { runUpdateRestart, standalone, type UpdateRestartIo, type UpdateRestartStandaloneDeps } from "../../src/cli/update-restart";
import type { UpdateRestartCandidate } from "../../src/cli/update-restart-candidate";
import type { UpdateRestartSupervisionDeps } from "../../src/cli/update-restart-supervision";

const roots: string[] = [];
const saved = { ocx: process.env.OPENCODEX_HOME, codex: process.env.CODEX_HOME };
afterEach(() => {
  if (saved.ocx === undefined) delete process.env.OPENCODEX_HOME; else process.env.OPENCODEX_HOME = saved.ocx;
  if (saved.codex === undefined) delete process.env.CODEX_HOME; else process.env.CODEX_HOME = saved.codex;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function fixture(platform: "darwin" | "linux" = "darwin") {
  const root = mkdtempSync(join(tmpdir(), "ocx-admission-")); roots.push(root);
  const config = join(root, "ocx"); const codex = join(root, "codex"); mkdirSync(config); mkdirSync(codex);
  process.env.OPENCODEX_HOME = config; process.env.CODEX_HOME = codex;
  writeFileSync(join(config, "config.json"), JSON.stringify({ hostname: "127.0.0.1" }));
  const record = join(config, "service-state.json");
  const state = { version: 2, backend: "scheduler", codexHome: codex, opencodexHome: config, revision: 1, bunPath: "/fixture/bun-a" };
  writeFileSync(record, JSON.stringify(state));
  let supervisionState = "inactive";
  const supervision: UpdateRestartSupervisionDeps = { platform, now: () => 1000,
    run: () => platform === "darwin" ? { status: supervisionState === "inactive" ? 113 : supervisionState === "active" ? 0 : 5, stdout: "", stderr: "" }
      : { status: 0, stdout: `LoadState=loaded\nActiveState=${supervisionState}\nMainPID=${supervisionState === "active" ? 321 : 0}\n`, stderr: "" } };
  const homeDeps: UpdateRestartHomeDeps = { record: { platform, paths: () => [record], definitionPath: () => join(root, "definition") }, supervision };
  const home = readUpdateRestartHome(homeDeps);
  const target: UpdateRestartCandidate["target"] = { pid: 123, port: 23456, hostname: "127.0.0.1", source: "runtime", version: "2.76.0" };
  const candidate: UpdateRestartCandidate = { home, target, runtime: { pid: 123, port: 23456, hostname: "127.0.0.1", attestationSecret: "a".repeat(43) }, cliVersion: "2.77.0" };
  const validator: UpdateRestartStandaloneDeps = { platform, expectedHome: home, home: homeDeps, supervision,
    command: () => "bun /fixture/opencodex/src/cli/index.ts start --port 23456", parent: () => "1",
    manager: { verifyPid: pid => pid, expectedCommand: () => "fixture" } };
  const calls = { checks: 0, stops: 0, spawns: 0, releases: 0 };
  const live = { ...target, pid: 456, version: "2.77.0" };
  const io: UpdateRestartIo = {
    now: () => 1000, acquire: () => ({ release: () => { calls.releases++; } }),
    home: () => readUpdateRestartHome(homeDeps), checkHome: expected => { calls.checks++; assertUpdateRestartHome(expected, 5000, homeDeps); },
    runtime: () => candidate.runtime, standalone: selected => standalone(selected, 5000, validator), runtimeReady: () => true,
    stop: async (_candidate, _deadline, beforeStop) => { beforeStop(); calls.stops++; }, stopped: async () => true,
    start: () => { calls.spawns++; return { pid: 456, exitCode: null, signalCode: null }; },
    observe: async () => live, wait: async () => {},
  };
  return { root, record, state, home, homeDeps, candidate, validator, calls, io, supervision,
    flip: (next = "active") => { supervisionState = next; },
    drift: () => writeFileSync(record, JSON.stringify({ ...state, bunPath: "/fixture/bun-b" })),
  };
}
test("production validator and transaction admit installed but unloaded POSIX records", async () => {
  for (const platform of ["darwin", "linux"] as const) {
    const s = fixture(platform);
    expect(standalone(s.candidate.target, 5000, s.validator)).toBe(true);
    expect(await runUpdateRestart(s.candidate, 5000, s.io)).toMatchObject({ ok: true, live: { pid: 456 } });
    expect(s.calls).toEqual({ checks: 6, stops: 1, spawns: 1, releases: 1 });
  }
});
test("supervision activation or uncertainty at every parent checkpoint is terminal", async () => {
  for (const platform of ["darwin", "linux"] as const) for (const next of ["active", "unknown"]) for (let checkpoint = 1; checkpoint <= 6; checkpoint++) {
    const s = fixture(platform); const check = s.io.checkHome;
    s.io.checkHome = home => { if (s.calls.checks + 1 === checkpoint) s.flip(next); check(home); };
    const result = await runUpdateRestart(s.candidate, 5000, s.io);
    expect(result.ok).toBe(false); expect(s.calls.checks).toBe(checkpoint);
    expect(s.calls.stops).toBe(checkpoint <= 2 ? 0 : 1); expect(s.calls.spawns).toBe(checkpoint <= 4 ? 0 : 1);
  }
});
test("same-revision provenance drift refuses at each parent checkpoint without a second launch", async () => {
  for (let checkpoint = 1; checkpoint <= 6; checkpoint++) {
    const s = fixture(); const check = s.io.checkHome;
    s.io.checkHome = home => { if (s.calls.checks + 1 === checkpoint) s.drift(); check(home); };
    expect((await runUpdateRestart(s.candidate, 5000, s.io)).ok).toBe(false);
    expect(s.calls.checks).toBe(checkpoint); expect(s.calls.stops).toBe(checkpoint <= 2 ? 0 : 1);
    expect(s.calls.spawns).toBe(checkpoint <= 4 ? 0 : 1);
  }
});
test("drift during the async runtime-readiness wait refuses synchronously before spawn", async () => {
  const s = fixture(); let ready = true;
  s.io.runtimeReady = () => ready;
  s.io.stopped = async () => { ready = false; return true; };
  s.io.wait = async () => { s.drift(); ready = true; };
  expect(await runUpdateRestart(s.candidate, 5000, s.io)).toEqual({ ok: false, code: "update_restart_prelaunch_failed" });
  expect(s.calls.stops).toBe(1); expect(s.calls.spawns).toBe(0);
});
test("retained PID-bound manager probe timeout refuses before any stop POST", async () => {
  for (const platform of ["darwin", "linux"] as const) {
    const s = fixture(platform); let probes = 0;
    s.validator.supervision = { ...s.supervision, run: (command, args, budget) => {
      expect(budget).toBe(2000);
      if (++probes > (platform === "darwin" ? 2 : 1)) throw new Error("timeout");
      return s.supervision.run!(command, args, budget);
    } };
    expect(await runUpdateRestart(s.candidate, 5000, s.io)).toEqual({ ok: false, code: "update_restart_eligibility_failed", reason: "unverifiable_ancestry" });
    expect(s.calls.stops).toBe(0); expect(s.calls.spawns).toBe(0);
  }
});
test("claims, malformed records, Windows, foreground and invalid ancestry remain refused", () => {
  for (const refusal of ["claim", "invalid", "windows", "foreground", "ancestry"] as const) {
    const s = fixture();
    if (refusal === "claim") writeFileSync(s.record, JSON.stringify({ ...s.state, ownership: { owner: "cli", installId: "fixture-owner", consentGeneration: 1 } }));
    if (refusal === "invalid") writeFileSync(s.record, "{bad");
    if (refusal === "windows") { s.validator.platform = "win32"; s.homeDeps.record!.platform = "win32"; expect(() => readUpdateRestartHome(s.homeDeps)).toThrow(); }
    if (refusal === "foreground") s.validator.parent = () => "321";
    if (refusal === "ancestry") s.validator.command = () => null;
    expect(() => standalone(s.candidate.target, 5000, s.validator)).toThrow();
  }
});
test("child requires a schema-1 lowercase digest before acquiring or checking state", () => {
  for (const serviceRecord of [undefined, null, { schema: 2, digest: "a".repeat(64) }, { schema: 1, digest: "A".repeat(64) }, { schema: 1, digest: "a".repeat(63) }, { schema: 1, digest: 42 }]) {
    const s = fixture(); let checks = 0;
    const marker = { home: { ...s.home, serviceRecord }, version: "2.77.0", port: 23456, hostname: "127.0.0.1", deadlineAt: 5000 };
    expect(() => admitUpdateRestartChild(["start", "--port", "23456"], { env: { [UPDATE_RESTART_CHILD_ENV]: JSON.stringify(marker) }, now: () => 1000,
      checkHome: () => { checks++; }, acquire: () => { checks++; return { release() {} }; } })).toThrow("update_restart_child_marker_invalid");
    expect(checks).toBe(0);
  }
});
test("child validates fingerprint and supervision before/under lease and every publication guard", () => {
  for (const drift of ["record", "supervision", "replacement"] as const) for (let checkpoint = 1; checkpoint <= 7; checkpoint++) {
    const s = fixture(); let checks = 0; let acquires = 0; let releases = 0;
    const mutate = () => {
      if (drift === "record") s.drift();
      if (drift === "supervision") s.flip();
      if (drift === "replacement") { renameSync(s.record, s.record + ".old"); writeFileSync(s.record, JSON.stringify(s.state)); }
    };
    const marker = { home: s.home, version: "2.77.0", port: 23456, hostname: "127.0.0.1", deadlineAt: 5000 };
    const invoke = () => {
      const guard = admitUpdateRestartChild(["start", "--port", "23456"], { env: { [UPDATE_RESTART_CHILD_ENV]: JSON.stringify(marker) }, now: () => 1000, version: () => "2.77.0",
        checkHome: home => { if (++checks === checkpoint) mutate(); assertUpdateRestartHome(home, 5000, s.homeDeps); }, checkState: () => {},
        acquire: () => { acquires++; return { release: () => { releases++; } }; }, onExit: () => {}, armDeadline: () => () => {},
      })!;
      guard.check(); // before bind
      guard.check(); // after bind
      guard.check(); // before PID publication
      guard.check(); // before runtime publication
      guard.complete();
    };
    expect(invoke).toThrow(drift === "supervision" ? "update_restart_supervision_unverified" : "update_restart_home_changed");
    expect(checks).toBe(checkpoint); expect(acquires).toBe(checkpoint === 1 ? 0 : 1);
    expect(releases).toBe(checkpoint === 2 ? 1 : 0);
  }
});

test("record rewrite during bounded supervision or retained manager evidence refuses before stop", async () => {
  for (const phase of ["home-probe", "manager-probe"] as const) {
    const s = fixture(); let probes = 0;
    if (phase === "home-probe") {
      const run = s.supervision.run!;
      s.supervision.run = (command, args, budget) => { s.drift(); return run(command, args, budget); };
    } else {
      const run = s.supervision.run!;
      s.validator.supervision = { ...s.supervision, run: (command, args, budget) => {
        if (++probes === 3) s.drift();
        return run(command, args, budget);
      } };
    }
    expect((await runUpdateRestart(s.candidate, 5000, s.io)).ok).toBe(false);
    expect(s.calls.stops).toBe(0); expect(s.calls.spawns).toBe(0);
  }
});

test("retained systemd evidence cannot relax MainPID-zero or remaining-deadline admission", async () => {
  for (const output of ["LoadState=not-found\nActiveState=inactive\nMainPID=321", "LoadState=not-found\nActiveState=inactive", "LoadState=loaded\nActiveState=activating\nMainPID=0"]) {
    const s = fixture("linux"); let probes = 0;
    s.validator.supervision = { ...s.supervision, run: (command, args, budget) => {
      if (++probes === 2) return { status: 0, stdout: output, stderr: "" };
      return s.supervision.run!(command, args, budget);
    } };
    expect(await runUpdateRestart(s.candidate, 5000, s.io)).toEqual({ ok: false, code: "update_restart_eligibility_failed", reason: "unverifiable_ancestry" });
    expect(s.calls.stops).toBe(0); expect(s.calls.spawns).toBe(0);
  }
  const s = fixture("linux"); let now = 1000; let probes = 0;
  s.validator.supervision = { ...s.supervision, now: () => now, run: (command, args, budget) => {
    probes++; now = 5000;
    return s.supervision.run!(command, args, budget);
  } };
  expect((await runUpdateRestart(s.candidate, 5000, s.io)).ok).toBe(false);
  expect(probes).toBe(1); expect(s.calls.stops).toBe(0); expect(s.calls.spawns).toBe(0);
});
