import { createFileRoute, Link } from "@tanstack/react-router";
import { Mail, Link2, ShieldX, LogIn } from "lucide-react";
import { AppShell, Card, Empty, ScoreRing, SevBadge, Btn } from "@/components/AppShell";
import { useStore, fmt } from "@/lib/trusttrace";
import { IncidentActions } from "./index";

export const Route = createFileRoute("/attack-chain")({
  head: () => ({
    meta: [
      { title: "Attack-Chain Explorer — TrustTrace AI" },
      { name: "description", content: "Correlated timeline linking phishing, link clicks and suspicious logins." },
      { property: "og:title", content: "Attack-Chain Explorer — TrustTrace AI" },
      { property: "og:description", content: "Visual correlation of attack-chain evidence." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Chain,
});

const ICON = { phishing: Mail, link: Link2, login_fail: ShieldX, login_success: LogIn, info: Mail };

function Chain() {
  const { chain, incidents } = useStore();
  const inc = incidents.find((i) => i.id === "INC-2001");
  if (!chain)
    return (
      <AppShell title="Attack-Chain Explorer" subtitle="Correlate related events into a single story">
        <Empty title="No correlated chain yet">
          <p>Run the account takeover scenario to generate linked events.</p>
          <Link to="/demo"><Btn className="mt-4">Go to Demo Center</Btn></Link>
        </Empty>
      </AppShell>
    );
  return (
    <AppShell title="Attack-Chain Explorer" subtitle="Possible account takeover — user a.sharma">
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="flex flex-col items-center gap-3 text-center">
          <ScoreRing score={chain.score} />
          <p className="font-display font-semibold">Correlated risk score</p>
          {inc && <div className="flex flex-col items-center gap-2"><span className="text-xs capitalize text-muted-foreground">{inc.id} · {inc.status}</span><IncidentActions id={inc.id} status={inc.status} /></div>}
        </Card>
        <Card className="lg:col-span-2">
          <h2 className="mb-2 font-display font-semibold">Why this is risky</h2>
          <p className="text-sm leading-relaxed text-muted-foreground">
            The same user received a high-scoring phishing email, visited its link within minutes, and the account then saw a burst of failed logins
            followed by a success — all from an IP, country and device never seen for this user, within a {"<"}30 minute window (+10 time-proximity bonus).
            Each signal alone is weak; together they form a pattern consistent with credential phishing followed by account takeover.
          </p>
          <p className="mt-3 rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-3 text-xs text-sev-medium">
            Uncertainty: this is a heuristic correlation of synthetic data, not proof of compromise. The user may have mistyped their password while travelling on a VPN. Confirm with the user and review session activity before taking disruptive action.
          </p>
        </Card>
      </div>
      <Card>
        <h2 className="mb-5 font-display font-semibold">Timeline & linked evidence</h2>
        <ol className="relative ml-4 space-y-6 border-l border-border">
          {chain.steps.map((s) => {
            const Icon = ICON[s.event.type];
            return (
              <li key={s.event.id} className="ml-6">
                <span className="absolute -left-4 grid h-8 w-8 place-items-center rounded-full bg-gradient-brand shadow-glow"><Icon className="h-4 w-4 text-primary-foreground" /></span>
                <div className="rounded-lg border border-border bg-secondary/40 p-4">
                  <div className="flex flex-wrap items-center gap-2"><SevBadge s={s.event.severity} /><span className="font-mono text-xs text-muted-foreground">{fmt(s.event.time)} · {s.event.source}</span><span className="ml-auto font-mono text-sm text-primary">+{s.contribution}</span></div>
                  <p className="mt-1 text-sm font-medium">{s.event.detail}</p>
                  <p className="text-xs text-muted-foreground">{s.reason}</p>
                </div>
              </li>
            );
          })}
        </ol>
      </Card>
      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <h3 className="mb-2 font-display font-semibold">Phishing evidence ({chain.phish.score}/100)</h3>
          <ul className="space-y-1 text-sm">{chain.phish.indicators.map((i) => <li key={i.label} className="flex justify-between gap-2"><span>{i.label} <code className="text-xs text-accent">{i.evidence}</code></span><span className="font-mono text-primary">+{i.weight}</span></li>)}</ul>
        </Card>
        <Card>
          <h3 className="mb-2 font-display font-semibold">Login evidence</h3>
          <ul className="space-y-1 text-sm">{chain.loginFindings.map((f) => <li key={f.rule}><span className="font-medium">{f.rule}:</span> <span className="text-muted-foreground">{f.evidence}</span></li>)}</ul>
        </Card>
      </div>
    </AppShell>
  );
}
