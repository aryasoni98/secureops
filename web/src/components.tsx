// Shared layout primitives, severity styling, and route guards used by every
// dashboard page. Keeping them in one file avoids 10+ trivially small modules.

import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { token, type Finding } from "./api";
import { setup } from "./setup";

export const authed = (): boolean => Boolean(token.get());

// ----------------------------- shell ---------------------------------------

const TABS: ReadonlyArray<readonly [string, string]> = [
  ["/findings", "Findings"],
  ["/compliance", "Compliance"],
  ["/graph", "Graph"],
  ["/remediation", "Remediation"],
  ["/usage", "Usage"],
  ["/license-status", "License"],
  ["/profile", "Profile"],
];

export function TopNav() {
  const nav = useNavigate();
  const loc = useLocation();
  return (
    <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-10">
      <div className="max-w-7xl mx-auto flex items-center gap-4 px-4 py-3">
        <Link to="/findings" className="font-semibold text-emerald-400">
          SecureOps
        </Link>
        <nav className="flex gap-3 text-sm">
          {TABS.map(([to, label]) => {
            const active = loc.pathname.startsWith(to);
            return (
              <Link
                key={to}
                to={to}
                className={`px-3 py-1 rounded ${
                  active ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white"
                }`}
              >
                {label}
              </Link>
            );
          })}
        </nav>
        <button
          onClick={() => {
            token.clear();
            nav("/license");
          }}
          className="ml-auto text-sm text-slate-400 hover:text-rose-400"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}

export function Page({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="max-w-7xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">{title}</h1>
      {children}
    </div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <>
      <TopNav />
      {children}
    </>
  );
}

// ----------------------------- severity ------------------------------------

const SEVERITY_CLASSES: Record<Finding["severity"], string> = {
  critical: "bg-rose-500/20 text-rose-300 border-rose-500/50",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  medium: "bg-amber-500/20 text-amber-300 border-amber-500/50",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/50",
  info: "bg-slate-500/20 text-slate-300 border-slate-500/50",
};

export function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return (
    <span className={`px-2 py-0.5 border rounded text-xs ${SEVERITY_CLASSES[severity]}`}>
      {severity}
    </span>
  );
}

// ----------------------------- guards --------------------------------------

export function RequireAuth({ children }: { children: JSX.Element }) {
  return authed() ? children : <Navigate to="/license" replace />;
}

export function RequireSetup({ children }: { children: JSX.Element }) {
  if (!authed()) return <Navigate to="/license" replace />;
  if (!setup.done("llm")) return <Navigate to="/setup/llm-keys" replace />;
  if (!setup.done("cloud")) return <Navigate to="/setup/cloud" replace />;
  if (!setup.done("scan")) return <Navigate to="/setup/scan" replace />;
  return children;
}

// ----------------------------- small UI helpers ----------------------------

export function PrimaryButton(props: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { className = "", ...rest } = props;
  return (
    <button
      {...rest}
      className={`bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold px-4 py-2 rounded ${className}`}
    />
  );
}

export function PillButton({
  active,
  children,
  ...rest
}: { active: boolean } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className={`px-3 py-1 rounded text-xs ${
        active ? "bg-emerald-500 text-slate-950" : "bg-slate-800"
      }`}
    >
      {children}
    </button>
  );
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: React.ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="p-4 text-slate-500">
        {children}
      </td>
    </tr>
  );
}
