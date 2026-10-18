import { useSyncExternalStore } from "react";

export type Severity = "critical" | "high" | "medium" | "low";
export type IncidentStatus = "open" | "acknowledged" | "investigating" | "resolved";

export interface SecurityEvent {
  id: string;
  time: string;
  type: "phishing" | "link" | "login_fail" | "login_success" | "info";
  source: string;
  user: string;
  detail: string;
  severity: Severity;
}
export interface LoginEvent {
  id: string;
  time: string;
  user: string;
  ip: string;
  country: string;
  device: string;
  success: boolean;
}
export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  created: string;
  score: number;
  eventIds: string[];
}
export interface Indicator {
  label: string;
  weight: number;
  evidence: string;
}

/* ---------------- Phishing heuristics ---------------- */
const RULES: { label: string; weight: number; test: (t: string) => string | null }[] = [
  { label: "Urgency language", weight: 15, test: (t) => match(t, /\b(urgent|immediately|within 24 hours|act now|suspended|final notice)\b/i) },
  { label: "Credential request", weight: 20, test: (t) => match(t, /\b(verify your (account|password|identity)|confirm your password|login details|reset your password)\b/i) },
  { label: "Raw IP address in URL", weight: 15, test: (t) => match(t, /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i) },
  { label: "Suspicious top-level domain", weight: 10, test: (t) => match(t, /https?:\/\/[^\s/]+\.(xyz|top|click|zip|ru|tk|info|live)\b/i) },
  { label: "Brand lookalike domain", weight: 15, test: (t) => match(t, /(micr0soft|paypa1|g00gle|app1e|rn icrosoft|micros0ft|amaz0n|-secure-login|account-verify)/i) },
  { label: "URL shortener", weight: 10, test: (t) => match(t, /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd)\//i) },
  { label: "Insecure HTTP link", weight: 5, test: (t) => match(t, /http:\/\/[^\s]+/i) },
  { label: "Financial lure", weight: 10, test: (t) => match(t, /\b(invoice|payment|wire transfer|gift card|refund|bank)\b/i) },
  { label: "Suspicious attachment reference", weight: 10, test: (t) => match(t, /\b\w+\.(exe|scr|js|vbs|html?|iso|zip)\b/i) },
  { label: "Generic greeting", weight: 5, test: (t) => match(t, /\b(dear (customer|user|client|valued))\b/i) },
  { label: "@ symbol inside URL", weight: 10, test: (t) => match(t, /https?:\/\/[^\s]*@[^\s]+/i) },
];
function match(t: string, r: RegExp) {
  const m = t.match(r);
  return m ? m[0] : null;
}

export function analyzePhishing(text: string) {
  const indicators: Indicator[] = [];
  for (const r of RULES) {
    const e = r.test(text);
    if (e) indicators.push({ label: r.label, weight: r.weight, evidence: e });
  }
  const score = Math.min(100, indicators.reduce((s, i) => s + i.weight, 0));
  const level = score >= 70 ? "High" : score >= 40 ? "Medium" : score > 0 ? "Low" : "Minimal";
  const actions =
    score >= 70
      ? ["Do not click links or open attachments", "Report the message to the security team", "If credentials were entered, reset the password and revoke sessions", "Block the sender domain at the mail gateway"]
      : score >= 40
        ? ["Verify the sender through a separate, known channel", "Hover over links to inspect real destinations", "Report to security if still unsure"]
        : ["No strong indicators found — still apply normal caution", "Verify unexpected requests with the sender directly"];
  return { score, level, indicators, actions };
}

/* ---------------- Login detection ---------------- */
export interface LoginFinding {
  rule: string;
  user: string;
  weight: number;
  evidence: string;
  eventIds: string[];
}
const KNOWN_DEVICES: Record<string, string[]> = {
  "a.sharma": ["MacBook Pro / Safari"],
  "r.patel": ["Windows 11 / Edge"],
  "j.lee": ["iPhone 15 / Safari", "Windows 11 / Chrome"],
};
const HOME: Record<string, string> = { "a.sharma": "IN", "r.patel": "IN", "j.lee": "US" };

export function analyzeLogins(logins: LoginEvent[]): LoginFinding[] {
  const out: LoginFinding[] = [];
  const byUser: Record<string, LoginEvent[]> = {};
  logins.forEach((l) => (byUser[l.user] ??= []).push(l));
  for (const [user, evs] of Object.entries(byUser)) {
    const sorted = [...evs].sort((a, b) => a.time.localeCompare(b.time));
    const fails = sorted.filter((e) => !e.success);
    if (fails.length >= 3)
      out.push({ rule: "Repeated failed logins", user, weight: 25, evidence: `${fails.length} failures from ${[...new Set(fails.map((f) => f.ip))].join(", ")}`, eventIds: fails.map((f) => f.id) });
    const odd = sorted.filter((e) => !(KNOWN_DEVICES[user] ?? []).includes(e.device));
    if (odd.length)
      out.push({ rule: "Unfamiliar device", user, weight: 15, evidence: [...new Set(odd.map((o) => o.device))].join(", "), eventIds: odd.map((o) => o.id) });
    const foreign = sorted.filter((e) => HOME[user] && e.country !== HOME[user]);
    if (foreign.length)
      out.push({ rule: "Unusual location", user, weight: 15, evidence: `Logins from ${[...new Set(foreign.map((f) => f.country))].join(", ")} (usual: ${HOME[user]})`, eventIds: foreign.map((f) => f.id) });
    for (let i = 0; i < sorted.length; i++) {
      const cur = sorted[i]!;
      if (cur.success && fails.length >= 3 && i >= 3 && sorted.slice(i - 3, i).every((e) => !e.success)) {
        out.push({ rule: "Success after failure burst", user, weight: 30, evidence: `Successful login at ${fmt(cur.time)} right after 3+ failures`, eventIds: [cur.id] });
      }
    }
  }
  return out;
}

export function fmt(iso: string) {
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
}

/* ---------------- Synthetic data ---------------- */
const base = Date.UTC(2026, 9, 18, 6, 0);
const t = (min: number) => new Date(base + min * 60000).toISOString();

export const SAMPLE_PHISH = `From: IT Security <security@micr0soft-account-verify.xyz>
Subject: URGENT: Your mailbox will be suspended

Dear user,
We detected unusual activity. Verify your account immediately within 24 hours or access will be suspended.
Click here: http://micr0soft-account-verify.xyz/login?u=a.sharma
Attached: Mailbox_Restore.html`;

const BASELINE_EVENTS: SecurityEvent[] = [
  { id: "b1", time: t(-300), type: "info", source: "EDR", user: "r.patel", detail: "Routine signature update", severity: "low" },
  { id: "b2", time: t(-240), type: "login_success", source: "IdP", user: "j.lee", detail: "Login from iPhone 15 / Safari, US", severity: "low" },
  { id: "b3", time: t(-120), type: "info", source: "Firewall", user: "—", detail: "Port scan blocked from 45.9.20.11", severity: "medium" },
];
const BASELINE_LOGINS: LoginEvent[] = [
  { id: "l1", time: t(-400), user: "a.sharma", ip: "49.36.12.8", country: "IN", device: "MacBook Pro / Safari", success: true },
  { id: "l2", time: t(-240), user: "j.lee", ip: "73.22.140.5", country: "US", device: "iPhone 15 / Safari", success: true },
  { id: "l3", time: t(-200), user: "r.patel", ip: "103.21.4.77", country: "IN", device: "Windows 11 / Edge", success: false },
  { id: "l4", time: t(-199), user: "r.patel", ip: "103.21.4.77", country: "IN", device: "Windows 11 / Edge", success: true },
];
const BASELINE_INCIDENTS: Incident[] = [
  { id: "INC-1001", title: "Port scan blocked at perimeter", severity: "medium", status: "acknowledged", created: t(-120), score: 35, eventIds: ["b3"] },
];

export const SCENARIO_EVENTS: SecurityEvent[] = [
  { id: "s1", time: t(0), type: "phishing", source: "Mail Gateway", user: "a.sharma", detail: "Email 'URGENT: Your mailbox will be suspended' from micr0soft-account-verify.xyz", severity: "high" },
  { id: "s2", time: t(4), type: "link", source: "Web Proxy", user: "a.sharma", detail: "Visited http://micr0soft-account-verify.xyz/login", severity: "high" },
  { id: "s3", time: t(9), type: "login_fail", source: "IdP", user: "a.sharma", detail: "5 failed logins from 185.220.101.4 (DE)", severity: "medium" },
  { id: "s4", time: t(13), type: "login_success", source: "IdP", user: "a.sharma", detail: "Successful login from 185.220.101.4 (DE), Linux / Firefox", severity: "critical" },
];
export const SCENARIO_LOGINS: LoginEvent[] = [
  ...[9, 10, 10.5, 11, 12].map((m, i) => ({ id: `sl${i}`, time: t(m), user: "a.sharma", ip: "185.220.101.4", country: "DE", device: "Linux / Firefox", success: false })),
  { id: "sl5", time: t(13), user: "a.sharma", ip: "185.220.101.4", country: "DE", device: "Linux / Firefox", success: true },
];

/* ---------------- Store ---------------- */
interface State {
  events: SecurityEvent[];
  logins: LoginEvent[];
  incidents: Incident[];
  scenarioRan: boolean;
  chain: ChainResult | null;
}
export interface ChainResult {
  score: number;
  steps: { event: SecurityEvent; contribution: number; reason: string }[];
  phish: ReturnType<typeof analyzePhishing>;
  loginFindings: LoginFinding[];
}

const initial: State = { events: BASELINE_EVENTS, logins: BASELINE_LOGINS, incidents: BASELINE_INCIDENTS, scenarioRan: false, chain: null };
let state: State = initial;
const subs = new Set<() => void>();
const set = (p: Partial<State>) => {
  state = { ...state, ...p };
  subs.forEach((f) => f());
};

export function useStore() {
  return useSyncExternalStore(
    (f) => (subs.add(f), () => subs.delete(f)),
    () => state,
    () => initial,
  );
}

export function correlate(events: SecurityEvent[], logins: LoginEvent[]): ChainResult | null {
  const user = "a.sharma";
  const ev = events.filter((e) => e.user === user && e.id.startsWith("s")).sort((a, b) => a.time.localeCompare(b.time));
  if (ev.length < 2) return null;
  const phish = analyzePhishing(SAMPLE_PHISH);
  const loginFindings = analyzeLogins(logins).filter((f) => f.user === user);
  const reasons: Record<string, [number, string]> = {
    phishing: [Math.round(phish.score * 0.25), `Phishing heuristic score ${phish.score}/100 contributes 25%`],
    link: [15, "User visited the link from the flagged email within minutes"],
    login_fail: [20, "Failure burst from a new IP shortly after the link was visited"],
    login_success: [30, "Successful login from the same unfamiliar IP/device right after failures"],
  };
  const steps = ev.map((e) => ({ event: e, contribution: reasons[e.type]?.[0] ?? 0, reason: reasons[e.type]?.[1] ?? "" }));
  const span = (new Date(ev[ev.length - 1]!.time).getTime() - new Date(ev[0]!.time).getTime()) / 60000;
  const timeBonus = span <= 30 ? 10 : 0;
  const score = Math.min(100, steps.reduce((s, x) => s + x.contribution, 0) + timeBonus);
  return { score, steps, phish, loginFindings };
}

export const actions = {
  async runScenario() {
    await new Promise((r) => setTimeout(r, 1200));
    const events = [...state.events.filter((e) => !e.id.startsWith("s")), ...SCENARIO_EVENTS];
    const logins = [...state.logins.filter((l) => !l.id.startsWith("sl")), ...SCENARIO_LOGINS];
    const chain = correlate(events, logins);
    const incidents = state.incidents.filter((i) => i.id !== "INC-2001");
    if (chain)
      incidents.unshift({ id: "INC-2001", title: "Possible account takeover — a.sharma", severity: chain.score >= 75 ? "critical" : "high", status: "open", created: SCENARIO_EVENTS[3]!.time, score: chain.score, eventIds: SCENARIO_EVENTS.map((e) => e.id) });
    set({ events, logins, incidents, chain, scenarioRan: true });
  },
  reset() {
    set(initial);
  },
  setStatus(id: string, status: IncidentStatus) {
    set({ incidents: state.incidents.map((i) => (i.id === id ? { ...i, status } : i)) });
  },
};
