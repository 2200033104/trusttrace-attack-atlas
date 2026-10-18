import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { Loader2, Play, RotateCcw, CheckCircle2 } from "lucide-react";
import { AppShell, Card, Btn } from "@/components/AppShell";
import { useStore, actions } from "@/lib/trusttrace";

export const Route = createFileRoute("/demo")({
  head: () => ({
    meta: [
      { title: "Demo Center — TrustTrace AI" },
      { name: "description", content: "Run a synthetic account takeover scenario end to end." },
      { property: "og:title", content: "Demo Center — TrustTrace AI" },
      { property: "og:description", content: "Run a synthetic account takeover scenario." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Demo,
});

const STEPS = ["Phishing email delivered to a.sharma", "User clicks the suspicious link", "5 failed logins from 185.220.101.4 (DE)", "Successful login from same unfamiliar device"];

function Demo() {
  const { scenarioRan, chain } = useStore();
  const [loading, setLoading] = useState(false);
  const run = async () => { setLoading(true); await actions.runScenario(); setLoading(false); };
  return (
    <AppShell title="Demo Center" subtitle="Inject synthetic events and run the full detection pipeline">
      <Card>
        <h2 className="font-display text-lg font-semibold">Account Takeover Scenario</h2>
        <p className="mt-1 text-sm text-muted-foreground">Populates synthetic mail, proxy and identity events, runs phishing and login rules, correlates them and opens an incident.</p>
        <ol className="mt-4 space-y-2">
          {STEPS.map((s, i) => (
            <li key={s} className="flex items-center gap-3 text-sm">
              {scenarioRan ? <CheckCircle2 className="h-4 w-4 text-sev-low" /> : <span className="grid h-5 w-5 place-items-center rounded-full bg-muted text-[10px]">{i + 1}</span>}{s}
            </li>
          ))}
        </ol>
        <div className="mt-5 flex flex-wrap gap-2">
          <Btn onClick={run} disabled={loading}>{loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}{loading ? "Running analysis…" : scenarioRan ? "Re-run scenario" : "Run Account Takeover Scenario"}</Btn>
          <Btn variant="ghost" onClick={() => actions.reset()} disabled={loading || !scenarioRan}><RotateCcw className="h-4 w-4" />Reset data</Btn>
        </div>
      </Card>
      {scenarioRan && chain && (
        <Card className="shadow-glow">
          <p className="font-display font-semibold">Analysis complete — correlated risk {chain.score}/100</p>
          <p className="text-sm text-muted-foreground">Incident INC-2001 opened. Treat as a lead to investigate, not a confirmed breach.</p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Link to="/attack-chain"><Btn>View attack chain</Btn></Link>
            <Link to="/"><Btn variant="ghost">Dashboard</Btn></Link>
            <Link to="/logins"><Btn variant="ghost">Login detections</Btn></Link>
          </div>
        </Card>
      )}
    </AppShell>
  );
}
