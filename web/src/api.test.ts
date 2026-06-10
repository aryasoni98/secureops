import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { api, ApiError, token } from "./api";

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

describe("rawFetch error handling", () => {
  beforeEach(() => {
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => store.set(k, v),
      removeItem: (k: string) => store.delete(k),
      clear: () => store.clear(),
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("throws ApiError with a sanitized message on non-2xx (no body leak)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("secret internal detail", { status: 500 })),
    );
    const err = await api.getLicense().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(500);
    expect(err.message).toBe("Request failed (500)");
    expect(err.message).not.toContain("secret");
  });

  it("sends the bearer token when present", async () => {
    token.set("tok-123");
    const fetchMock = vi.fn(async () => Response.json({ tier: "pro", expiry: 0, features: [] }));
    vi.stubGlobal("fetch", fetchMock);
    await api.getLicense();
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer tok-123");
  });

  it("returns undefined for 204 No Content", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(api.denyRemediation("r1")).resolves.toBeUndefined();
  });
});
