import { afterEach, expect, test } from "bun:test";
import { chmodSync, lstatSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureUpdateRestartServiceRecord, assertUpdateRestartServiceRecord, type UpdateRestartServiceRecordDeps } from "../../src/cli/update-restart-service-record";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function setup() {
  const root = mkdtempSync(join(tmpdir(), "ocx-record-")); roots.push(root);
  const mirror = join(root, "mirror.json"); const authority = join(root, "authority.json"); const definition = join(root, "definition");
  let paths = [mirror, authority];
  const deps: UpdateRestartServiceRecordDeps = { platform: "darwin", paths: () => paths, definitionPath: () => definition };
  const state = { version: 2, backend: "scheduler", codexHome: join(root, "codex"), opencodexHome: root, revision: 4, bunPath: "/fixture/bun-a" };
  return { root, mirror, authority, definition, deps, state, paths: (next: string[]) => { paths = next; } };
}
test("captures absence, authority position and parses ownership from the captured bytes", () => {
  const s = setup(); const absent = captureUpdateRestartServiceRecord(s.deps);
  expect(absent.serviceRecord).toEqual({ schema: 1, digest: expect.stringMatching(/^[a-f0-9]{64}$/) });
  expect(absent.state.kind).toBe("none");
  writeFileSync(s.authority, JSON.stringify(s.state));
  const installed = captureUpdateRestartServiceRecord(s.deps);
  expect(installed.state).toMatchObject({ kind: "state", revision: 4, state: s.state });
  expect(installed.owner).toEqual({ kind: "none", revision: 4 });
  expect(installed.serviceRecord.digest).not.toBe(absent.serviceRecord.digest);
  s.paths([s.authority, s.mirror]);
  expect(() => assertUpdateRestartServiceRecord(installed.serviceRecord, s.deps)).toThrow("update_restart_home_changed");
});
test("same revision provenance, same-size restored-mtime edit and identical-byte replacement refuse", () => {
  for (const edit of ["provenance", "mtime", "replace", "mode", "definition", "create-definition", "delete-definition"] as const) {
    const s = setup(); const raw = JSON.stringify(s.state); writeFileSync(s.authority, raw); chmodSync(s.authority, 0o644);
    if (edit !== "create-definition") writeFileSync(s.definition, "definition-a");
    const before = lstatSync(s.authority); const captured = captureUpdateRestartServiceRecord(s.deps);
    if (edit === "provenance") writeFileSync(s.authority, raw.replace("bun-a", "bun-b"));
    if (edit === "mtime") { writeFileSync(s.authority, raw.replace("bun-a", "bun-b")); utimesSync(s.authority, before.atime, before.mtime); }
    if (edit === "replace") { writeFileSync(s.authority + ".next", raw); renameSync(s.authority + ".next", s.authority); }
    if (edit === "mode") chmodSync(s.authority, 0o600);
    if (edit === "definition") writeFileSync(s.definition, "definition-b");
    if (edit === "create-definition") writeFileSync(s.definition, "definition-a");
    if (edit === "delete-definition") unlinkSync(s.definition);
    expect(() => assertUpdateRestartServiceRecord(captured.serviceRecord, s.deps)).toThrow("update_restart_home_changed");
  }
});
test("mirror and authority creation, deletion, conflict and candidate membership drift refuse", () => {
  for (const edit of ["create-mirror", "delete-mirror", "create-authority", "delete-authority", "conflict", "membership"] as const) {
    const s = setup(); const raw = JSON.stringify(s.state);
    if (edit !== "create-mirror") writeFileSync(s.mirror, raw);
    if (edit !== "create-authority") writeFileSync(s.authority, raw);
    const captured = captureUpdateRestartServiceRecord(s.deps);
    if (edit === "create-mirror") writeFileSync(s.mirror, raw);
    if (edit === "create-authority") writeFileSync(s.authority, raw);
    if (edit === "delete-mirror") unlinkSync(s.mirror);
    if (edit === "delete-authority") unlinkSync(s.authority);
    if (edit === "conflict") writeFileSync(s.mirror, raw.replace("bun-a", "bun-b"));
    if (edit === "membership") s.paths([s.mirror, s.authority, join(s.root, "new.json")]);
    expect(() => assertUpdateRestartServiceRecord(captured.serviceRecord, s.deps)).toThrow("update_restart_home_changed");
  }
});
test("lock and runtime publication do not change the service-record digest", () => {
  const s = setup(); const captured = captureUpdateRestartServiceRecord(s.deps);
  for (const name of ["runtime-port.json", "proxy.pid", "service-state.json.lock"]) writeFileSync(join(s.root, name), "fixture");
  expect(() => assertUpdateRestartServiceRecord(captured.serviceRecord, s.deps)).not.toThrow();
});
test("invalid state, symlinked state or definition, EACCES and unstable reads refuse", () => {
  for (const edit of ["invalid", "state-link", "definition-link", "eacces", "read-drift", "path-drift", "absent-drift"] as const) {
    const s = setup(); writeFileSync(s.authority, JSON.stringify(s.state));
    if (edit === "invalid") writeFileSync(s.authority, "{bad");
    if (edit === "state-link" || edit === "definition-link") {
      const path = edit === "state-link" ? s.authority : s.definition;
      if (edit === "state-link") unlinkSync(path);
      symlinkSync(s.authority === path ? s.mirror : s.authority, path);
    }
    if (edit === "eacces") s.deps.lstat = () => { throw Object.assign(new Error("private detail"), { code: "EACCES" }); };
    if (edit === "read-drift" || edit === "path-drift") s.deps.read = fd => {
      const bytes = readFileSync(fd);
      if (edit === "read-drift") writeFileSync(s.authority, JSON.stringify({ ...s.state, bunPath: "/fixture/bun-b" }));
      else { renameSync(s.authority, s.authority + ".old"); writeFileSync(s.authority, bytes); }
      return bytes;
    };
    if (edit === "absent-drift") s.deps.read = fd => { writeFileSync(s.mirror, JSON.stringify(s.state)); return readFileSync(fd); };
    expect(() => captureUpdateRestartServiceRecord(s.deps)).toThrow("update_restart_service_record_unverified");
  }
});
test("physical directory aliases retain fingerprint but record symlinks do not", () => {
  const s = setup(); writeFileSync(s.authority, JSON.stringify(s.state));
  const captured = captureUpdateRestartServiceRecord(s.deps);
  const alias = join(s.root, "alias"); symlinkSync(s.root, alias, process.platform === "win32" ? "junction" : "dir");
  s.paths([join(alias, "mirror.json"), join(alias, "authority.json")]);
  expect(() => assertUpdateRestartServiceRecord(captured.serviceRecord, s.deps)).not.toThrow();
});
test("an owned record stays owned even when its bytes are fingerprinted", () => {
  const s = setup(); writeFileSync(s.authority, JSON.stringify({ ...s.state, ownership: { owner: "desktop", installId: "fixture-install", consentGeneration: 1 } }));
  expect(captureUpdateRestartServiceRecord(s.deps).owner.kind).toBe("owned");
});
