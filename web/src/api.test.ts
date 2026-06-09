import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { token } from "./api";

// Smoke tests for the API client helpers. Keeps the unit suite from being empty
// so CI catches regressions in the JWT storage contract Playwright depends on.

describe("token storage", () => {
  beforeEach(() => {
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => store.set(k, v),
      removeItem: (k: string) => store.delete(k),
      clear: () => store.clear(),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("round-trips a token via set/get/clear", () => {
    expect(token.get()).toBeNull();
    token.set("abc");
    expect(token.get()).toBe("abc");
    token.clear();
    expect(token.get()).toBeNull();
  });
});
