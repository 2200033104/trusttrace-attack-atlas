import { Link, useRouterState } from "@tanstack/react-router";
import { LayoutDashboard, MailWarning, KeyRound, Workflow, PlayCircle, ShieldCheck, Menu, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { actions, type IncidentStatus } from "@/lib/trusttrace";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/phishing", label: "Phishing Analyzer", icon: MailWarning },
  { to: "/logins", label: "Login Analyzer", icon: KeyRound },
  { to: "/attack-chain", label: "Attack-Chain Explorer", icon: Workflow },
  { to: "/demo", label: "Demo Center", icon: PlayCircle },
] as const;

export function AppShell({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [open, setOpen] = useState(false);
  return (
    <div className="flex min-h-screen w-full">
      <aside className={`fixed inset-y-0 left-0 z-40 w-64 border-r border-border bg-sidebar p-4 transition-transform lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="mb-8 flex items-center gap-2 px-2">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-brand"><ShieldCheck className="h-5 w-5 text-primary-foreground" /></div>
          <div>
            <div className="font-display text-lg font-bold leading-none">TrustTrace<span className="text-accent"> AI</span></div>
            <div className="text-[11px] text-muted-foreground">Attack-chain detection</div>
          </div>
          <button className="ml-auto lg:hidden" onClick={() => setOpen(false)} aria-label="Close menu"><X className="h-5 w-5" /></button>
        </div>
        <nav className="space-y-1">
          {nav.map((n) => {
            const active = path === n.to;
            return (
              <Link key={n.to} to={n.to} onClick={() => setOpen(false)}
                className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${active ? "bg-sidebar-accent text-foreground shadow-glow" : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground"}`}>
                <n.icon className={`h-4 w-4 ${active ? "text-accent" : ""}`} />{n.label}
              </Link>
            );
          })}
        </nav>
        <p className="absolute bottom-4 left-4 right-4 text-[11px] leading-relaxed text-muted-foreground">Synthetic data only. Detections are heuristic signals, not proof of an attack.</p>
      </aside>
      {open && <div className="fixed inset-0 z-30 bg-background/70 lg:hidden" onClick={() => setOpen(false)} />}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-64">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border bg-background/80 px-4 py-4 backdrop-blur md:px-8">
          <button className="lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></button>
          <div>
            <h1 className="font-display text-xl font-bold md:text-2xl">{title}</h1>
            {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
          </div>
        </header>
        <main className="flex-1 space-y-6 p-4 md:p-8">{children}</main>
      </div>
    </div>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-xl border border-border bg-card p-5 shadow-card ${className}`}>{children}</div>;
}

export function SevBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
    high: "bg-sev-high/15 text-sev-high border-sev-high/40",
    medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
    low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  };
  return <span className={`inline-flex rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${map[s] ?? map.low}`}>{s}</span>;
}

export function Btn({ children, variant = "primary", className = "", ...p }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" }) {
  const v = variant === "primary" ? "bg-gradient-brand text-primary-foreground shadow-glow hover:opacity-90" : "border border-border bg-secondary text-secondary-foreground hover:bg-muted";
  return <button {...p} className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition disabled:opacity-50 ${v} ${className}`}>{children}</button>;
}

export function ScoreRing({ score }: { score: number }) {
  const color = score >= 70 ? "var(--sev-critical)" : score >= 40 ? "var(--sev-medium)" : "var(--sev-low)";
  return (
    <div className="relative grid h-32 w-32 place-items-center rounded-full" style={{ background: `conic-gradient(${color} ${score * 3.6}deg, var(--muted) 0)` }}>
      <div className="grid h-24 w-24 place-items-center rounded-full bg-card">
        <span className="font-display text-3xl font-bold">{score}</span>
      </div>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-border p-10 text-center">
      <p className="font-medium">{title}</p>
      <div className="mt-2 text-sm text-muted-foreground">{children}</div>
    </div>
  );
}

export function IncidentActions({ id, status }: { id: string; status: IncidentStatus }) {
  if (status === "resolved") return <span className="text-xs text-sev-low">Resolved</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {status === "open" && <Btn variant="ghost" className="px-2 py-1 text-xs" onClick={() => actions.setStatus(id, "acknowledged")}>Acknowledge</Btn>}
      {status !== "investigating" && <Btn variant="ghost" className="px-2 py-1 text-xs" onClick={() => actions.setStatus(id, "investigating")}>Investigate</Btn>}
      <Btn variant="ghost" className="px-2 py-1 text-xs" onClick={() => actions.setStatus(id, "resolved")}>Resolve</Btn>
    </div>
  );
}

