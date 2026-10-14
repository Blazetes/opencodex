import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyMainHardLockFallbackOverride } from "../../src/server/responses/main-hard-lock-routing";
import { resolveMainAccountHardLockFallback } from "../../src/codex/main-account-hard-lock";
import { captureMainQuotaWriter, clearMainAccountInfoCache, observeMainQuotaIdentity } from "../../src/codex/main-account-cache";
import { clearAccountQuota, setAccountQuotaFromParsed, type StoredAccountQuota } from "../../src/codex/quota";
import { saveCodexAccountCredential } from "../../src/codex/account-store";
import { NATIVE_RESERVE_MODEL } from "../../src/codex/catalog/native-models";
import type { OcxConfig } from "../../src/types";
import { removeTreeWithRetry } from "../helpers/remove-tree";

const now = Date.UTC(2026, 8, 5);
const FALLBACK = { model: "deepseek/deepseek-chat", reasoningEffort: "low" };
let home: string;
let previousHome: string | undefined;

beforeEach(() => {
  previousHome = process.env.OPENCODEX_HOME;
  home = mkdtempSync(join(tmpdir(), "ocx-main-lock-fallback-"));
  process.env.OPENCODEX_HOME = home;
  clearAccountQuota();
  clearMainAccountInfoCache();
  observeMainQuotaIdentity("fallback-account-a");
});

afterEach(() => {
  clearAccountQuota();
  clearMainAccountInfoCache();
  if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
  else process.env.OPENCODEX_HOME = previousHome;
  removeTreeWithRetry(home);
});

function observe(quota: Omit<StoredAccountQuota, "updatedAt">): void {
  const writer = captureMainQuotaWriter("fallback-account-a");
  if (!writer) throw new Error("fixture identity was not observed");
  setAccountQuotaFromParsed("__main__", quota, undefined, writer);
}

function config(overrides: Partial<OcxConfig> = {}): OcxConfig {
  return { providers: {}, codexAccounts: [], ...overrides } as OcxConfig;
}

function withPoolAccount(target: OcxConfig): OcxConfig {
  saveCodexAccountCredential("pool-a", {
    accessToken: "access-pool-a",
    refreshToken: "refresh-pool-a",
    expiresAt: Date.now() + 5 * 60_000,
    chatgptAccountId: "acct-pool-a",
  });
  return { ...target, codexAccounts: [{ id: "pool-a", email: "pool@example.test", isMain: false, plan: "pro" }] } as OcxConfig;
}

describe("main-account hard-lock fallback resolution", () => {
  test("a malformed section disables the reroute instead of half-applying", () => {
    expect(resolveMainAccountHardLockFallback(config())).toBeUndefined();
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: { model: "  " } } as OcxConfig)).toBeUndefined();
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: { model: " deepseek/deepseek-chat" } } as OcxConfig)).toBeUndefined();
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: { model: "a b" } } as OcxConfig)).toBeUndefined();
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: { model: "deepseek/deepseek-chat", reasoningEffort: "extreme" } } as OcxConfig)).toBeUndefined();
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: FALLBACK } as OcxConfig)).toEqual(FALLBACK);
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: { model: "combo/x" } } as OcxConfig))
      .toEqual({ model: "combo/x" });
    // The dashboard row keeps the configured model while its switch is off: enabled false
    // pauses the reroute without forgetting the destination, and a malformed enabled flag
    // is a hand edit the section boundary never accepts.
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: { ...FALLBACK, enabled: false } } as OcxConfig)).toBeUndefined();
    expect(resolveMainAccountHardLockFallback({ codexMainAccountHardLockFallback: { ...FALLBACK, enabled: true } } as OcxConfig)).toEqual(FALLBACK);
  });
});

describe("applyMainHardLockFallbackOverride", () => {
  test("a blocked lock with no eligible account rewrites the model and the effort", () => {
    observe({ weeklyPercent: 98 });
    const body: Record<string, unknown> = { model: "gpt-5.3", reasoning: { effort: "high" } };
    expect(applyMainHardLockFallbackOverride(body, config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>)))
      .toEqual({ sourceModel: "gpt-5.3", targetModel: "deepseek/deepseek-chat" });
    expect(body.model).toBe("deepseek/deepseek-chat");
    expect(body.reasoning).toEqual({ effort: "low" });
  });

  test("each blocking window governs on its own", () => {
    const cfg = config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>);
    observe({ shortPercent: 90 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).not.toBeNull();
    observe({ shortPercent: 0 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).toBeNull();
    observe({ weeklyPercent: 98 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).not.toBeNull();
    observe({ weeklyPercent: 0 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).toBeNull();
  });

  test("a monthly-only account governs on monthly; supplementary monthly data never blocks", () => {
    const cfg = config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>);
    // No short or weekly evidence at all: monthly is the account's only window.
    observe({ monthlyPercent: 99 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).not.toBeNull();
    observe({ monthlyPercent: 50 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).toBeNull();
    // Supplementary monthly data on a 5h/weekly account never becomes a lock.
    observe({ shortPercent: 10, weeklyPercent: 10, monthlyPercent: 99 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).toBeNull();
  });

  test("release is the same observation that admits: dropping below the threshold stops the rewrite", () => {
    const cfg = config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>);
    observe({ weeklyPercent: 99 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).not.toBeNull();
    observe({ weeklyPercent: 97.99 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, cfg)).toBeNull();
  });

  test("unknown usage, the opt-out, and a missing section all keep the refusal behavior", () => {
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>))).toBeNull();
    observe({ weeklyPercent: 100 });
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, config({ codexMainAccountHardLock: false, codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>))).toBeNull();
    expect(applyMainHardLockFallbackOverride({ model: "gpt-5.3" }, config())).toBeNull();
  });

  test("an eligible pool account keeps the request on Codex", () => {
    observe({ weeklyPercent: 100 });
    const cfg = withPoolAccount(config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>));
    const body: Record<string, unknown> = { model: "gpt-5.3" };
    expect(applyMainHardLockFallbackOverride(body, cfg)).toBeNull();
    expect(body.model).toBe("gpt-5.3");
  });

  test("only bare Codex-native selectors qualify", () => {
    observe({ weeklyPercent: 100 });
    const cfg = config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>);
    for (const model of ["deepseek/deepseek-chat", "combo/x", "openai-codex/gpt-5.3", NATIVE_RESERVE_MODEL]) {
      const body: Record<string, unknown> = { model };
      expect(applyMainHardLockFallbackOverride(body, cfg)).toBeNull();
      expect(body.model).toBe(model);
    }
  });

  test("a Codex-native fallback target never applies: the refusal is the honest answer", () => {
    observe({ weeklyPercent: 100 });
    const body: Record<string, unknown> = { model: "gpt-5.3" };
    expect(applyMainHardLockFallbackOverride(body, config({ codexMainAccountHardLockFallback: { model: "gpt-5.4" } } as Partial<OcxConfig>))).toBeNull();
    expect(body.model).toBe("gpt-5.3");
  });

  test("a fallback without an effort leaves the request's own reasoning untouched", () => {
    observe({ weeklyPercent: 100 });
    const cfg = config({ codexMainAccountHardLockFallback: { model: "deepseek/deepseek-chat" } } as Partial<OcxConfig>);
    const body: Record<string, unknown> = { model: "gpt-5.3", reasoning: { effort: "high" } };
    expect(applyMainHardLockFallbackOverride(body, cfg)).toEqual({ sourceModel: "gpt-5.3", targetModel: "deepseek/deepseek-chat" });
    expect(body.model).toBe("deepseek/deepseek-chat");
    expect(body.reasoning).toEqual({ effort: "high" });
  });

  test("a body without a usable model selector is never touched", () => {
    observe({ weeklyPercent: 100 });
    const cfg = config({ codexMainAccountHardLockFallback: FALLBACK } as Partial<OcxConfig>);
    expect(applyMainHardLockFallbackOverride(null, cfg)).toBeNull();
    expect(applyMainHardLockFallbackOverride([], cfg)).toBeNull();
    expect(applyMainHardLockFallbackOverride({ model: "" }, cfg)).toBeNull();
    expect(applyMainHardLockFallbackOverride({ model: 42 }, cfg)).toBeNull();
  });
});
