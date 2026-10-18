import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Loader2 } from "lucide-react";
import { AppShell, Card, Btn, ScoreRing, Empty } from "@/components/AppShell";
import { analyzePhishing, SAMPLE_PHISH } from "@/lib/trusttrace";

export const Route = createFileRoute("/phishing")({
  head: () => ({
    meta: [
      { title: "Phishing Analyzer — TrustTrace AI" },
      { name: "description", content: "Score emails and URLs for phishing risk with transparent heuristic rules." },
      { property: "og:title", content: "Phishing Analyzer — TrustTrace AI" },
      { property: "og:description", content: "Transparent heuristic phishing risk scoring." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Phishing,
});

function Phishing() {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [res, setRes] = useState<ReturnType<typeof analyzePhishing> | null>(null);
  const run = () => {
    setLoading(true);
    setTimeout(() => { setRes(analyzePhishing(text)); setLoading(false); }, 600);
  };
  return (
    <AppShell title="Phishing Analyzer" subtitle="Paste an email or URL to score it with deterministic rules">
      <Card>
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} placeholder="Paste email content or a URL…"
          className="w-full rounded-lg border border-input bg-background p-3 font-mono text-sm outline-none focus:ring-2 focus:ring-ring" />
        <div className="mt-3 flex flex-wrap gap-2">
          <Btn onClick={run} disabled={!text.trim() || loading}>{loading && <Loader2 className="h-4 w-4 animate-spin" />}Analyse</Btn>
          <Btn variant="ghost" onClick={() => setText(SAMPLE_PHISH)}>Load sample phishing email</Btn>
          <Btn variant="ghost" onClick={() => setText("https://www.wikipedia.org/")}>Load benign URL</Btn>
          <Btn variant="ghost" onClick={() => { setText(""); setRes(null); }}>Clear</Btn>
        </div>
      </Card>
      {!res ? <Empty title="No analysis yet">Paste content and click Analyse.</Empty> : (
        <div className="grid gap-6 lg:grid-cols-3">
          <Card className="flex flex-col items-center gap-3 text-center">
            <ScoreRing score={res.score} />
            <p className="font-display text-lg font-semibold">{res.level} risk</p>
            <p className="text-xs text-muted-foreground">Score is the sum of matched rule weights, capped at 100. Heuristics can produce false positives and miss novel attacks — this does not prove the message is malicious.</p>
          </Card>
          <Card className="lg:col-span-2">
            <h2 className="mb-3 font-display font-semibold">Suspicious indicators & evidence</h2>
            {res.indicators.length === 0 ? <p className="text-sm text-muted-foreground">No rules matched.</p> : (
              <ul className="space-y-2">
                {res.indicators.map((i) => (
                  <li key={i.label} className="flex items-start justify-between gap-3 rounded-lg bg-secondary/50 p-3">
                    <div><p className="text-sm font-medium">{i.label}</p><code className="break-all text-xs text-accent">"{i.evidence}"</code></div>
                    <span className="shrink-0 font-mono text-sm text-primary">+{i.weight}</span>
                  </li>
                ))}
              </ul>
            )}
            <h2 className="mb-2 mt-5 font-display font-semibold">Recommended actions</h2>
            <ul className="list-inside list-disc space-y-1 text-sm text-muted-foreground">{res.actions.map((a) => <li key={a}>{a}</li>)}</ul>
          </Card>
        </div>
      )}
    </AppShell>
  );
}
