import { createFileRoute, Link } from "@tanstack/react-router";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell } from "recharts";
import { AppShell, Card, SevBadge, Empty, IncidentActions } from "@/components/AppShell";
import { useStore, fmt } from "@/lib/trusttrace";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — TrustTrace AI" },
      { name: "description", content: "SOC overview of incidents, severity and recent synthetic security events." },
      { property: "og:title", content: "Dashboard — TrustTrace AI" },
      { property: "og:description", content: "SOC overview of incidents, severity and recent security events." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Dashboard,
});

const SEVS = ["critical", "high", "medium", "low"] as const;

function Dashboard() {
  const s = useStore();
  const open = s.incidents.filter((i) => i.status !== "resolved");
  const counts = SEVS.map((sev) => ({ sev, n: s.events.filter((e) => e.severity === sev).length }));
  const events = [...s.events].sort((a, b) => b.time.localeCompare(a.time));
  return (
    <AppShell title="Security Dashboard" subtitle="Overview of synthetic telemetry and active incidents">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card><p className="text-sm text-muted-foreground">Total incidents</p><p className="font-display text-3xl font-bold">{s.incidents.length}</p></Card>
        <Card><p className="text-sm text-muted-foreground">Open / active</p><p className="font-display text-3xl font-bold text-accent">{open.length}</p></Card>
        <Card><p className="text-sm text-muted-foreground">Events ingested</p><p className="font-display text-3xl font-bold">{s.events.length}</p></Card>
        <Card><p className="text-sm text-muted-foreground">Logins tracked</p><p className="font-display text-3xl font-bold">{s.logins.length}</p></Card>
      </div>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {counts.map((c) => (
          <Card key={c.sev} className="flex items-center justify-between"><SevBadge s={c.sev} /><span className="font-display text-2xl font-bold">{c.n}</span></Card>
        ))}
      </div>
      <div className="grid gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-display font-semibold">Incidents</h2>
            {!s.scenarioRan && <Link to="/demo" className="text-sm text-accent hover:underline">Run demo scenario →</Link>}
          </div>
          {s.incidents.length === 0 ? <Empty title="No incidents" /> : (
            <div className="space-y-3">
              {s.incidents.map((i) => (
                <div key={i.id} className="flex flex-col gap-3 rounded-lg border border-border bg-secondary/40 p-4 md:flex-row md:items-center">
                  <div className="flex-1">
                    <div className="flex items-center gap-2"><SevBadge s={i.severity} /><span className="font-mono text-xs text-muted-foreground">{i.id}</span><span className="text-xs capitalize text-muted-foreground">· {i.status}</span></div>
                    <p className="mt-1 font-medium">{i.title}</p>
                    <p className="text-xs text-muted-foreground">{fmt(i.created)} · risk score {i.score}/100</p>
                  </div>
                  <div className="flex flex-col gap-2 md:items-end">
                    <IncidentActions id={i.id} status={i.status} />
                    {i.id === "INC-2001" && <Link to="/attack-chain" className="text-xs text-accent hover:underline">View attack chain →</Link>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card>
          <h2 className="mb-4 font-display font-semibold">Events by severity</h2>
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={counts}>
                <XAxis dataKey="sev" stroke="var(--muted-foreground)" fontSize={12} />
                <YAxis allowDecimals={false} stroke="var(--muted-foreground)" fontSize={12} />
                <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", borderRadius: 8 }} cursor={{ fill: "var(--muted)" }} />
                <Bar dataKey="n" radius={[6, 6, 0, 0]}>
                  {counts.map((c) => <Cell key={c.sev} fill={`var(--sev-${c.sev})`} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>
      <Card>
        <h2 className="mb-4 font-display font-semibold">Recent alerts & events</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-muted-foreground"><tr><th className="py-2 pr-4">Time</th><th className="pr-4">Source</th><th className="pr-4">User</th><th className="pr-4">Detail</th><th>Severity</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-t border-border"><td className="whitespace-nowrap py-2.5 pr-4 font-mono text-xs">{fmt(e.time)}</td><td className="pr-4">{e.source}</td><td className="pr-4 font-mono text-xs">{e.user}</td><td className="pr-4 text-muted-foreground">{e.detail}</td><td><SevBadge s={e.severity} /></td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </AppShell>
  );
}
