import { expect, test } from "bun:test";
import { probeUpdateRestartSupervision, runBoundedUpdateRestartSupervisor, type UpdateRestartSupervisionDeps } from "../../src/cli/update-restart-supervision";

const reply = (status: number | null, stdout = "") => ({ status, stdout, stderr: "" });
test("launchd probes both domains regardless of registration presence", () => {
  const calls: string[][] = [];
  const deps: UpdateRestartSupervisionDeps = { platform: "darwin", uid: 42, now: () => 100,
    run: (_command, args, budget) => { calls.push(args); expect(budget).toBe(1900); return reply(args[1]!.startsWith("gui/") ? 112 : 113); } };
  expect(probeUpdateRestartSupervision(2000, deps)).toBe("inactive");
  expect(calls).toEqual([["print", "gui/42/com.opencodex.proxy"], ["print", "user/42/com.opencodex.proxy"]]);
});
test("launchd loaded, uncertain, signalled and non-absence exits block", () => {
  for (const status of [0, 1, 3, 5, null]) {
    let calls = 0;
    expect(probeUpdateRestartSupervision(2000, { platform: "darwin", now: () => 100,
      run: () => reply(++calls === 1 ? status : 113) })).toBe(status === 0 ? "active" : "unknown");
    expect(calls).toBe(2);
  }
});
test("supervision honors remaining deadline before and after every command", () => {
  let now = 100; const budgets: number[] = [];
  const deps: UpdateRestartSupervisionDeps = { platform: "darwin", now: () => now,
    run: (_command, _args, budget) => { budgets.push(budget); now += 50; return reply(113); } };
  expect(probeUpdateRestartSupervision(5000, deps)).toBe("inactive"); expect(budgets).toEqual([2000, 2000]);
  now = 100; budgets.length = 0;
  expect(probeUpdateRestartSupervision(180, deps)).toBe("unknown"); expect(budgets).toEqual([80, 30]);
  expect(() => runBoundedUpdateRestartSupervisor("manager", [], 200, { now: () => 200, run: () => { throw new Error("must not run"); } })).toThrow();
  expect(probeUpdateRestartSupervision(1000, { platform: "darwin", now: () => 100, run: () => { throw new Error("timeout"); } })).toBe("unknown");
});
test("systemd requires explicit inactive state and MainPID zero", () => {
  for (const load of ["loaded", "not-found"]) {
    expect(probeUpdateRestartSupervision(2000, { platform: "linux", now: () => 100,
      run: () => reply(0, `LoadState=${load}\nActiveState=inactive\nMainPID=0\n`) })).toBe("inactive");
  }
  for (const [output, expected] of [
    ["LoadState=loaded\nActiveState=active\nMainPID=23", "active"],
    ["LoadState=loaded\nActiveState=inactive\nMainPID=23", "active"],
    ["LoadState=loaded\nActiveState=activating\nMainPID=0", "unknown"],
    ["LoadState=loaded\nActiveState=failed\nMainPID=0", "unknown"],
    ["LoadState=loaded\nActiveState=inactive", "unknown"],
    ["LoadState=loaded\nActiveState=inactive\nMainPID=0\nMainPID=0", "unknown"],
    ["LoadState=error\nActiveState=inactive\nMainPID=0", "unknown"],
    ["garbage", "unknown"],
  ]) expect(probeUpdateRestartSupervision(2000, { platform: "linux", now: () => 100, run: () => reply(0, output) })).toBe(expected!);
  expect(probeUpdateRestartSupervision(2000, { platform: "linux", now: () => 100, run: () => reply(1) })).toBe("unknown");
});
test("Windows and unsupported platforms never infer inactivity", () => {
  for (const platform of ["win32", "freebsd"] as const) expect(probeUpdateRestartSupervision(2000, { platform, run: () => { throw new Error("must not probe"); } })).toBe("unknown");
});
