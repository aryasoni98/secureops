// Shared layout primitives, severity styling, and route guards used by every
// dashboard page. Keeping them in one file avoids 10+ trivially small modules.
// All motion comes from framer-motion; ambient/background animation is pure
// CSS so it never blocks interaction.

import { motion, AnimatePresence } from "framer-motion";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { token, type Finding } from "./api";
import { setup } from "./setup";

export const authed = (): boolean => Boolean(token.get());

// ----------------------------- ambient background ---------------------------

/** Fixed aurora gradient blobs behind every screen (CSS-driven, GPU-cheap). */
export function AmbientBackground() {
  return (
    <div className="fixed inset-0 -z-10 overflow-hidden pointer-events-none" aria-hidden>
      <div className="absolute -top-40 -left-40 w-[36rem] h-[36rem] rounded-full bg-emerald-500/[0.07] blur-3xl animate-aurora" />
      <div className="absolute top-1/3 -right-48 w-[40rem] h-[40rem] rounded-full bg-cyan-500/[0.06] blur-3xl animate-aurora-slow" />
      <div className="absolute -bottom-48 left-1/4 w-[32rem] h-[32rem] rounded-full bg-violet-500/[0.05] blur-3xl animate-aurora" />
      <div
        className="absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          maskImage: "radial-gradient(ellipse at 50% 0%, black 0%, transparent 70%)",
          WebkitMaskImage: "radial-gradient(ellipse at 50% 0%, black 0%, transparent 70%)",
        }}
      />
    </div>
  );
}

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
    <motion.header
      initial={{ y: -24, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="border-b border-white/[0.06] bg-ink-950/70 backdrop-blur-xl sticky top-0 z-20"
    >
      <div className="max-w-7xl mx-auto flex items-center gap-5 px-4 py-3">
        <Link to="/findings" className="flex items-center gap-2 font-bold tracking-tight">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400" />
          </span>
          <span className="text-gradient text-lg">SecureOps</span>
        </Link>
        <nav className="flex gap-1 text-sm">
          {TABS.map(([to, label]) => {
            const active = loc.pathname.startsWith(to);
            return (
              <Link key={to} to={to} className="relative px-3 py-1.5 rounded-lg">
                {active && (
                  <motion.span
                    layoutId="nav-pill"
                    className="absolute inset-0 bg-white/[0.08] border border-white/[0.1] rounded-lg shadow-glow"
                    transition={{ type: "spring", stiffness: 400, damping: 32 }}
                  />
                )}
                <span
                  className={`relative z-10 transition-colors duration-200 ${
                    active ? "text-white" : "text-slate-400 hover:text-white"
                  }`}
                >
                  {label}
                </span>
              </Link>
            );
          })}
        </nav>
        <motion.button
          whileHover={{ scale: 1.04 }}
          whileTap={{ scale: 0.96 }}
          onClick={() => {
            token.clear();
            nav("/license");
          }}
          className="ml-auto text-sm text-slate-400 hover:text-rose-400 transition-colors"
        >
          Sign out
        </motion.button>
      </div>
    </motion.header>
  );
}

/** Stagger container used by Page so each page's children cascade in. */
const pageVariants = {
  hidden: { opacity: 0, y: 16 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] as const },
  },
};

export function Page({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <motion.div
      variants={pageVariants}
      initial="hidden"
      animate="show"
      className="max-w-7xl mx-auto p-6"
    >
      <div className="mb-6">
        <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
        <motion.div
          initial={{ scaleX: 0 }}
          animate={{ scaleX: 1 }}
          transition={{ duration: 0.6, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
          className="origin-left mt-2 h-[3px] w-16 rounded-full bg-gradient-to-r from-emerald-400 to-cyan-400"
        />
      </div>
      {children}
    </motion.div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <>
      <AmbientBackground />
      <TopNav />
      {children}
    </>
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
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 border rounded-full text-xs font-medium ${SEVERITY_CLASSES[severity]}`}
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

// ----------------------------- small UI helpers ----------------------------

export function PrimaryButton(props: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { className = "", children, ...rest } = props;
  return (
    <motion.button
      whileHover={{ scale: 1.03, boxShadow: "0 0 28px rgba(16,185,129,0.45)" }}
      whileTap={{ scale: 0.97 }}
      transition={{ type: "spring", stiffness: 500, damping: 30 }}
      {...(rest as object)}
      className={`bg-gradient-to-r from-emerald-500 to-teal-400 text-slate-950 font-semibold px-5 py-2 rounded-xl shadow-glow disabled:opacity-50 ${className}`}
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
      whileHover={{ scale: 1.06 }}
      whileTap={{ scale: 0.94 }}
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
        initial={{ opacity: 0, y: -8, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: -8 }}
        className="bg-rose-500/10 backdrop-blur border border-rose-500/40 text-rose-300 rounded-xl p-3 text-sm mb-4 flex items-center gap-3"
      >
        <span>{message}</span>
        {onRetry && (
          <button onClick={onRetry} className="underline hover:text-rose-200">
            Retry
          </button>
        )}
      </motion.div>
    </AnimatePresence>
  );
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: React.ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="p-6 text-slate-500 text-center">
        {children}
      </td>
    </tr>
  );
}

// ----------------------------- motion table helpers -------------------------

/** Table row that fades/slides in with a per-index stagger delay. */
export function MotionRow({
  index,
  children,
  ...rest
}: { index: number } & React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <motion.tr
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.35, delay: Math.min(index * 0.05, 0.5), ease: "easeOut" }}
      {...(rest as object)}
      className="border-t border-white/[0.06] hover:bg-white/[0.03] transition-colors duration-200"
    >
      {children}
    </motion.tr>
  );
}

/** Glass card that lifts slightly on hover. */
export function GlassCard({
  children,
  className = "",
  delay = 0,
}: {
  children: React.ReactNode;
  className?: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, delay, ease: [0.22, 1, 0.36, 1] }}
      whileHover={{ y: -3 }}
      className={`glass glass-hover shadow-card p-5 ${className}`}
    >
      {children}
    </motion.div>
  );
}
