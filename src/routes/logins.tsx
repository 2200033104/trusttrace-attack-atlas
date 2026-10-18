import { createFileRoute, Link } from "@tanstack/react-router";
import { AppShell, Card, Empty } from "@/components/AppShell";
import { useStore, analyzeLogins, fmt } from "@/lib/trusttrace";

export const Route = createFileRoute("/logins")({
  head: () => ({
    meta: [
      { title: "Login Analyzer — TrustTrace AI" },
      { name: "description", content: "Detect repeated failures, unfamiliar devices and suspicious login patterns." },
      { property: "og:title", content: "Login Analyzer — TrustTrace AI" },
      { property: "og:description", content: "Rule-based suspicious login detection." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Logins,
});

function Logins() {
  const { logins } = useStore();
  const findings = analyzeLogins(logins);
  const flagged = new Set(findings.flatMap((f) => f.eventIds));
  const rows = [...logins].sort((a, b) => b.time.localeCompare(a.time));
  return (
    <AppShell title="Login Analyzer" subtitle="Synthetic identity-provider events with rule-based detection">
      <Card>
        <h2 className="mb-3 font-display font-semibold">Detections</h2>
        {findings.length === 0 ? (
          <Empty title="No suspicious patterns detected">Run the <Link to="/demo" className="text-accent hover:underline">demo scenario</Link> to inject a takeover attempt.</Empty>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {findings.map((f, i) => (
              <div key={i} className="rounded-lg border border-border bg-secondary/40 p-4">
                <div className="flex justify-between"><p className="font-medium">{f.rule}</p><span className="font-mono text-sm text-primary">+{f.weight}</span></div>
                <p className="font-mono text-xs text-accent">{f.user}</p>
                <p className="mt-1 text-sm text-muted-foreground">{f.evidence}</p>
              </div>
            ))}
          </div>
        )}
        <p className="mt-3 text-xs text-muted-foreground">Rules: ≥3 failures per user; device not in known list; country differs from home; success directly after 3+ failures. Travel, VPNs or new laptops can trigger these legitimately.</p>
      </Card>
      <Card>
        <h2 className="mb-3 font-display font-semibold">Login events</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-muted-foreground"><tr><th className="py-2 pr-4">Time</th><th className="pr-4">User</th><th className="pr-4">IP</th><th className="pr-4">Country</th><th className="pr-4">Device</th><th className="pr-4">Result</th><th>Flag</th></tr></thead>
            <tbody>
              {rows.map((l) => (
                <tr key={l.id} className={`border-t border-border ${flagged.has(l.id) ? "bg-sev-high/5" : ""}`}>
                  <td className="whitespace-nowrap py-2.5 pr-4 font-mono text-xs">{fmt(l.time)}</td><td className="pr-4 font-mono text-xs">{l.user}</td><td className="pr-4 font-mono text-xs">{l.ip}</td><td className="pr-4">{l.country}</td><td className="pr-4">{l.device}</td>
                  <td className={`pr-4 ${l.success ? "text-sev-low" : "text-sev-critical"}`}>{l.success ? "Success" : "Failed"}</td>
                  <td>{flagged.has(l.id) ? <span className="text-xs text-sev-high">Suspicious</span> : <span className="text-xs text-muted-foreground">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </AppShell>
  );
}
