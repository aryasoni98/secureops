// Wizard progress flags stored in localStorage. Survives reload but local-only —
// the server is the source of truth for license/SSO state.

export type SetupStep = "llm" | "cloud" | "scan";

export const setup = {
  done: (k: SetupStep) => localStorage.getItem(`secureops.setup.${k}`) === "ok",
  mark: (k: SetupStep) => localStorage.setItem(`secureops.setup.${k}`, "ok"),
};
