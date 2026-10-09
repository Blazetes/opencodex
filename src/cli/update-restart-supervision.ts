import { execFileSync } from "node:child_process";
import { assertLiveServiceManagerAllowed } from "../service/guards";
import { LABEL, TASK } from "../service/state";

export type UpdateRestartSupervision = "inactive" | "active" | "unknown";
export interface UpdateRestartSupervisorReply { status: number | null; stdout: string; stderr: string }
export interface UpdateRestartSupervisionDeps {
  platform?: NodeJS.Platform;
  now?: () => number;
  uid?: number;
  run?: (command: string, args: string[], timeoutMs: number) => UpdateRestartSupervisorReply;
}
const PROBE_TIMEOUT_MS = 2000;
export const UPDATE_RESTART_SYSTEMD_ARGS = ["--user", "show", "-p", "LoadState", "-p", "ActiveState", "-p", "MainPID", "-p", "FragmentPath", "-p", "NeedDaemonReload", TASK];

function run(command: string, args: string[], timeout: number): UpdateRestartSupervisorReply {
  assertLiveServiceManagerAllowed("update restart supervision");
  try {
    return { status: 0, stdout: execFileSync(command, args, { encoding: "utf8", timeout,
      killSignal: "SIGKILL", maxBuffer: 64 * 1024, stdio: ["ignore", "pipe", "pipe"] }), stderr: "" };
  } catch (error) {
    const failure = error as { status?: number | null; signal?: string; code?: string; stdout?: Buffer; stderr?: Buffer };
    if (failure.signal || failure.code || !Number.isInteger(failure.status)) throw new Error("update_restart_supervision_unverified");
    return { status: failure.status!, stdout: failure.stdout?.toString() ?? "", stderr: failure.stderr?.toString() ?? "" };
  }
}

/** All manager evidence shares the transaction deadline, including the retained PID-bound probe. */
export function runBoundedUpdateRestartSupervisor(command: string, args: string[], deadlineAt: number, deps: UpdateRestartSupervisionDeps = {}) {
  const now = deps.now ?? Date.now;
  const remaining = deadlineAt - now();
  if (!Number.isFinite(remaining) || remaining <= 0) throw new Error("update_restart_supervision_unverified");
  const result = (deps.run ?? run)(command, args, Math.min(PROBE_TIMEOUT_MS, remaining));
  if (now() >= deadlineAt) throw new Error("update_restart_supervision_unverified");
  return result;
}

/** Registration presence is independent of liveness; only positive inactivity admits. */
export function probeUpdateRestartSupervision(deadlineAt: number, deps: UpdateRestartSupervisionDeps = {}): UpdateRestartSupervision {
  const platform = deps.platform ?? process.platform;
  if (platform === "darwin") {
    const uid = deps.uid ?? process.getuid?.() ?? 0;
    const states = [`gui/${uid}/${LABEL}`, `user/${uid}/${LABEL}`].map(target => {
      try {
        const result = runBoundedUpdateRestartSupervisor("/bin/launchctl", ["print", target], deadlineAt, deps);
        return result.status === 112 || result.status === 113 ? "inactive" : result.status === 0 ? "active" : "unknown";
      } catch { return "unknown"; }
    });
    return states.includes("unknown") ? "unknown" : states.includes("active") ? "active" : "inactive";
  }
  if (platform === "linux") {
    try {
      const result = runBoundedUpdateRestartSupervisor("systemctl", UPDATE_RESTART_SYSTEMD_ARGS, deadlineAt, deps);
      return classifyUpdateRestartSystemdSupervision(result);
    } catch { return "unknown"; }
  }
  return "unknown";
}

/** The retained manager observation must satisfy the same positive-inactivity contract. */
export function classifyUpdateRestartSystemdSupervision(result: UpdateRestartSupervisorReply): UpdateRestartSupervision {
  if (result.status !== 0) return "unknown";
  const fields = new Map<string, string>();
  for (const line of result.stdout.trim().split(/\r?\n/)) {
    const match = /^([A-Za-z]+)=(.*)$/.exec(line);
    if (!match || fields.has(match[1]!)) return "unknown";
    fields.set(match[1]!, match[2]!);
  }
  const pid = fields.get("MainPID");
  if (!pid || !/^\d+$/.test(pid) || !Number.isSafeInteger(Number(pid))) return "unknown";
  if (!["loaded", "not-found"].includes(fields.get("LoadState") ?? "")) return "unknown";
  if (fields.get("ActiveState") === "inactive" && pid === "0") return "inactive";
  return fields.get("ActiveState") === "active" || Number(pid) > 0 ? "active" : "unknown";
}
