// SecureOps dashboard SPA (PRODUCT.md Phase 8) - routing only.
// Wizard pages live in `wizard.tsx`, dashboard pages in `pages.tsx`, and
// shared chrome / guards in `components.tsx`.

import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { authed, RequireAuth, RequireSetup, Shell } from "./components";
import {
  Compliance,
  Findings,
  Graph,
  LicenseStatus,
  Profile,
  RemediationQueue,
  Usage,
} from "./pages";
import { LicenseActivation, SetupCloud, SetupLlmKeys, SetupScan } from "./wizard";

interface RouteSpec {
  path: string;
  element: JSX.Element;
  /** Wrap in {@link RequireAuth} (wizard step) or {@link RequireSetup}+Shell (dashboard page). */
  kind: "public" | "auth" | "dashboard";
}

const ROUTES: RouteSpec[] = [
  { path: "/license", element: <LicenseActivation />, kind: "public" },
  { path: "/setup/llm-keys", element: <SetupLlmKeys />, kind: "auth" },
  { path: "/setup/cloud", element: <SetupCloud />, kind: "auth" },
  { path: "/setup/scan", element: <SetupScan />, kind: "auth" },
  { path: "/findings", element: <Findings />, kind: "dashboard" },
  { path: "/compliance", element: <Compliance />, kind: "dashboard" },
  { path: "/graph", element: <Graph />, kind: "dashboard" },
  { path: "/remediation", element: <RemediationQueue />, kind: "dashboard" },
  { path: "/usage", element: <Usage />, kind: "dashboard" },
  { path: "/license-status", element: <LicenseStatus />, kind: "dashboard" },
  { path: "/profile", element: <Profile />, kind: "dashboard" },
];

function wrap(spec: RouteSpec): JSX.Element {
  switch (spec.kind) {
    case "public":
      return spec.element;
    case "auth":
      return <RequireAuth>{spec.element}</RequireAuth>;
    case "dashboard":
      return (
        <RequireSetup>
          <Shell>{spec.element}</Shell>
        </RequireSetup>
      );
  }
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        {ROUTES.map((r) => (
          <Route key={r.path} path={r.path} element={wrap(r)} />
        ))}
        <Route path="*" element={<Navigate to={authed() ? "/findings" : "/license"} replace />} />
      </Routes>
    </BrowserRouter>
  );
}
