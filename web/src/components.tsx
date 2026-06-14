// Shared layout primitives, severity styling, and route guards used by every
// dashboard page. Full-width shell with a persistent sidebar on large screens.

import { motion, AnimatePresence } from "framer-motion";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { token, type Finding } from "./api";
import { setup } from "./setup";

export const authed = (): boolean => Boolean(token.get());

// ----------------------------- navigation -----------------------------------

export const NAV_ITEMS = [
  { to: "/findings", label: "Findings", hint: "Review & fix issues" },
  { to: "/compliance", label: "Compliance", hint: "Framework gaps" },
  { to: "/graph", label: "Attack paths", hint: "Blast radius graph" },
  { to: "/remediation", label: "Remediation", hint: "HITL queue" },
  { to: "/usage", label: "Usage", hint: "Telemetry & stats" },
  { to: "/license-status", label: "License", hint: "Plan & features" },
  { to: "/profile", label: "Profile", hint: "Account settings" },
] as const;

function NavIcon({ name }: { name: string }) {
  const cls = "w-[18px] h-[18px] shrink-0 opacity-80";
  switch (name) {
    case "Findings":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      );
    case "Compliance":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M9 11l3 3L22 4" />
          <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
        </svg>
      );
    case "Attack paths":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="5" cy="12" r="2" />
          <circle cx="19" cy="5" r="2" />
          <circle cx="19" cy="19" r="2" />
          <path d="M7 12h6m4-5v10" />
        </svg>
      );
    case "Remediation":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77A6 6 0 0119 4l-3.77 3.77z" />
          <path d="M3 21l3.5-3.5M12 20h9" />
        </svg>
      );
    case "Usage":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 20V10M12 20V4M6 20v-6" />
        </svg>
      );
    case "License":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="5" width="18" height="14" rx="2" />
          <path d="M7 9h4M7 13h10" />
        </svg>
      );
    default:
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="8" r="4" />
          <path d="M4 20c0-4 4-6 8-6s8 2 8 6" />
        </svg>
      );
  }
}

function SideNav() {
  const loc = useLocation();
  const nav = useNavigate();
  return (
    <aside className="hidden lg:flex flex-col fixed inset-y-0 left-0 z-30 w-[240px] xl:w-[260px] border-r border-white/[0.06] bg-ink-950/85 backdrop-blur-xl">
      <div className="px-5 py-5 border-b border-white/[0.06]">
        <Link to="/findings" className="flex items-center gap-2.5 font-bold tracking-tight">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400" />
          </span>
          <span className="text-gradient text-lg">SecureOps</span>
        </Link>
        <p className="text-[11px] text-slate-500 mt-2 leading-snug">Cloud security dashboard</p>
      </div>
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-0.5">
        {NAV_ITEMS.map(({ to, label, hint }) => {
          const active = loc.pathname.startsWith(to);
          return (
            <Link
              key={to}
              to={to}
              title={hint}
              className={`group flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all duration-200 ${
                active
                  ? "bg-emerald-500/15 text-white border border-emerald-500/25 shadow-glow"
                  : "text-slate-400 hover:text-white hover:bg-white/[0.06] border border-transparent"
              }`}
            >
              <NavIcon name={label === "Attack paths" ? "Attack paths" : label} />
              <span className="flex flex-col min-w-0">
                <span className="font-medium truncate">{label}</span>
                <span className={`text-[10px] truncate ${active ? "text-emerald-300/70" : "text-slate-600 group-hover:text-slate-500"}`}>
                  {hint}
                </span>
              </span>
            </Link>
          );
        })}
      </nav>
      <div className="p-4 border-t border-white/[0.06]">
        <button
          type="button"
          onClick={() => {
            token.clear();
            nav("/license");
          }}
          className="w-full text-left px-3 py-2 rounded-lg text-sm text-slate-400 hover:text-rose-300 hover:bg-rose-500/10 transition-colors"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}

function MobileTopBar() {
  const loc = useLocation();
  const nav = useNavigate();
  return (
    <header className="lg:hidden sticky top-0 z-20 border-b border-white/[0.06] bg-ink-950/90 backdrop-blur-xl">
      <div className="flex items-center gap-3 px-4 py-3">
        <Link to="/findings" className="font-bold text-gradient shrink-0">SecureOps</Link>
        <button
          type="button"
          onClick={() => {
            token.clear();
            nav("/license");
          }}
          className="ml-auto text-xs text-slate-500 hover:text-rose-400"
        >
          Sign out
        </button>
      </div>
      <nav className="flex gap-1 overflow-x-auto px-3 pb-3 scrollbar-thin">
        {NAV_ITEMS.map(({ to, label }) => {
          const active = loc.pathname.startsWith(to);
          return (
            <Link
              key={to}
              to={to}
              className={`shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
                active
                  ? "bg-emerald-500/20 text-emerald-200 border border-emerald-500/30"
                  : "text-slate-400 bg-white/[0.04] border border-white/[0.06]"
              }`}
            >
              {label}
            </Link>
          );
        })}
      </nav>
    </header>
  );
}

// ----------------------------- ambient background ---------------------------

export function AmbientBackground() {
  return (
    <div className="fixed inset-0 -z-10 overflow-hidden pointer-events-none" aria-hidden>
      <div className="absolute -top-40 -left-40 w-[36rem] h-[36rem] rounded-full bg-emerald-500/[0.07] blur-3xl animate-aurora" />
      <div className="absolute top-1/3 -right-48 w-[40rem] h-[40rem] rounded-full bg-cyan-500/[0.06] blur-3xl animate-aurora-slow" />
      <div className="absolute -bottom-48 left-1/4 w-[32rem] h-[32rem] rounded-full bg-violet-500/[0.05] blur-3xl animate-aurora" />
      <div
        className="absolute inset-0 opacity-[0.12]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />
    </div>
  );
}

// ----------------------------- shell & page ---------------------------------

const pageVariants = {
  hidden: { opacity: 0, y: 12 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] as const },
  },
};

export function Page({
  title,
  subtitle,
  actions,
  narrow,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  /** Center content for wizard / license screens. */
  narrow?: boolean;
  children: React.ReactNode;
}) {
  return (
    <motion.div
      variants={pageVariants}
      initial="hidden"
      animate="show"
      className={`w-full px-4 sm:px-6 lg:px-8 xl:px-10 2xl:px-14 py-6 lg:py-8 ${narrow ? "max-w-3xl mx-auto" : ""}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-4 mb-6 lg:mb-8">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-white">{title}</h1>
          {subtitle && <p className="mt-2 text-sm sm:text-base text-slate-400 max-w-3xl leading-relaxed">{subtitle}</p>}
          <motion.div
            initial={{ scaleX: 0 }}
            animate={{ scaleX: 1 }}
            transition={{ duration: 0.5, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
            className="origin-left mt-3 h-[3px] w-20 rounded-full bg-gradient-to-r from-emerald-400 to-cyan-400"
          />
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2 shrink-0">{actions}</div>}
      </header>
      {children}
    </motion.div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex bg-ink-950">
      <AmbientBackground />
      <SideNav />
      <div className="flex-1 flex flex-col min-w-0 lg:pl-[240px] xl:pl-[260px]">
        <MobileTopBar />
        <main className="flex-1 w-full">{children}</main>
      </div>
    </div>
  );
}

// ----------------------------- layout helpers -------------------------------

export function PageToolbar({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`flex flex-wrap items-center justify-between gap-3 mb-5 ${className}`}>{children}</div>
  );
}

export function DataTable({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`glass shadow-card overflow-hidden w-full ${className}`}>
      <div className="overflow-x-auto">
        <table className="w-full text-sm min-w-[640px]">{children}</table>
      </div>
    </div>
  );
}

export function TableHead({ children }: { children: React.ReactNode }) {
  return (
    <thead className="text-slate-400 text-[11px] uppercase tracking-wider bg-white/[0.04] sticky top-0 z-10 backdrop-blur-sm">
      {children}
    </thead>
  );
}

export function QuickStats({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3 sm:gap-4 mb-6 w-full">
      {children}
    </div>
  );
}

export function QuickStat({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: "default" | "good" | "warn" | "bad";
}) {
  const toneClass =
    tone === "good"
      ? "text-emerald-400"
      : tone === "warn"
        ? "text-amber-400"
        : tone === "bad"
          ? "text-rose-400"
          : "text-gradient";
  return (
    <div className="glass p-4 rounded-xl border border-white/[0.06] hover:border-white/[0.12] transition-colors">
      <div className="text-[10px] sm:text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-xl sm:text-2xl font-bold ${toneClass}`}>{value}</div>
      {hint && <div className="text-[10px] text-slate-600 mt-1 truncate">{hint}</div>}
    </div>
  );
}

export function SplitLayout({
  sidebar,
  children,
}: {
  sidebar: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="grid xl:grid-cols-[240px_minmax(0,1fr)] gap-6 w-full items-start">
      <aside className="hidden xl:block sticky top-6">{sidebar}</aside>
      <div className="min-w-0 w-full">{children}</div>
    </div>
  );
}

// ----------------------------- severity ------------------------------------

const SEVERITY_CLASSES: Record<Finding["severity"], string> = {
  critical: "bg-rose-500/15 text-rose-300 border-rose-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  low: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  info: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

const SEVERITY_DOTS: Record<Finding["severity"], string> = {
  critical: "bg-rose-400",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-sky-400",
  info: "bg-slate-400",
};

export function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 border rounded-full text-xs font-medium capitalize ${SEVERITY_CLASSES[severity]}`}
    >
      <span className="relative flex h-1.5 w-1.5">
        {severity === "critical" && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-70" />
        )}
        <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${SEVERITY_DOTS[severity]}`} />
      </span>
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

// ----------------------------- buttons -------------------------------------

export function PrimaryButton(props: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { className = "", children, ...rest } = props;
  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      {...(rest as object)}
      className={`bg-gradient-to-r from-emerald-500 to-teal-400 text-slate-950 font-semibold px-4 py-2 rounded-xl shadow-glow disabled:opacity-50 text-sm ${className}`}
    >
      {children}
    </motion.button>
  );
}

export function SecondaryButton(props: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { className = "", children, ...rest } = props;
  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      {...(rest as object)}
      className={`px-4 py-2 rounded-xl text-sm font-medium bg-white/[0.06] border border-white/[0.1] text-slate-200 hover:bg-white/[0.1] disabled:opacity-50 ${className}`}
    >
      {children}
    </motion.button>
  );
}

export function PillButton({
  active,
  children,
  ...rest
}: { active: boolean } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <motion.button
      whileHover={{ scale: 1.04 }}
      whileTap={{ scale: 0.96 }}
      {...(rest as object)}
      className={`px-3.5 py-1.5 rounded-full text-xs font-medium border transition-colors duration-200 ${
        active
          ? "bg-gradient-to-r from-emerald-500 to-teal-400 text-slate-950 border-transparent shadow-glow"
          : "bg-white/[0.04] border-white/[0.08] text-slate-300 hover:bg-white/[0.08]"
      }`}
    >
      {children}
    </motion.button>
  );
}

export function ActionChip({
  variant,
  children,
  ...rest
}: { variant: "confirm" | "dismiss" | "escalate" | "approve" | "deny" | "ai" | "queue" } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const styles = {
    confirm: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/25",
    dismiss: "bg-rose-500/10 text-rose-300 border-rose-500/30 hover:bg-rose-500/20",
    escalate: "bg-amber-500/10 text-amber-300 border-amber-500/30 hover:bg-amber-500/20",
    approve: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/25",
    deny: "bg-rose-500/10 text-rose-300 border-rose-500/30 hover:bg-rose-500/20",
    ai: "bg-violet-500/15 text-violet-200 border-violet-500/30 hover:bg-violet-500/25",
    queue: "bg-cyan-500/10 text-cyan-200 border-cyan-500/30 hover:bg-cyan-500/20",
  };
  return (
    <button
      type="button"
      {...rest}
      className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors disabled:opacity-50 ${styles[variant]} ${rest.className ?? ""}`}
    >
      {children}
    </button>
  );
}

// ----------------------------- feedback ------------------------------------

export function ErrorNotice({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        className="bg-rose-500/10 backdrop-blur border border-rose-500/40 text-rose-300 rounded-xl p-3 text-sm mb-4 flex flex-wrap items-center gap-3"
        role="alert"
      >
        <span>{message}</span>
        {onRetry && (
          <button type="button" onClick={onRetry} className="underline hover:text-rose-200 font-medium">
            Retry
          </button>
        )}
      </motion.div>
    </AnimatePresence>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="glass p-10 sm:p-14 text-center w-full">
      <p className="text-lg font-medium text-slate-300 mb-2">{title}</p>
      {description && <p className="text-sm text-slate-500 mb-5 max-w-md mx-auto">{description}</p>}
      {action}
    </div>
  );
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: React.ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="p-10 text-slate-500 text-center text-sm">
        {children}
      </td>
    </tr>
  );
}

// ----------------------------- motion table helpers -------------------------

export function MotionRow({
  index,
  children,
  ...rest
}: { index: number } & React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <motion.tr
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3, delay: Math.min(index * 0.04, 0.4), ease: "easeOut" }}
      {...(rest as object)}
      className="border-t border-white/[0.06] hover:bg-white/[0.03] transition-colors duration-150"
    >
      {children}
    </motion.tr>
  );
}

export function GlassCard({
  children,
  className = "",
  delay = 0,
  hover = true,
}: {
  children: React.ReactNode;
  className?: string;
  delay?: number;
  hover?: boolean;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, ease: [0.22, 1, 0.36, 1] }}
      whileHover={hover ? { y: -2 } : undefined}
      className={`glass shadow-card p-5 ${className}`}
    >
      {children}
    </motion.div>
  );
}
