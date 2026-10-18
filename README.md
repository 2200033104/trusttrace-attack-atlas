# Trusttrace Attack Atlas

Build a complete, functional MVP for TrustTrace AI, an AI-powered cybersecurity attack-chain detection platform. Build everything in one pass to minimise credit usage.

DESIGN: Premium dark navy SOC dashboard, purple and cyan accents, responsive layout, professional charts, consistent sidebar, polished typography.

Implement these five sections:

Dashboard: incident counts, severity cards, recent alerts, and synthetic security events.

Phishing Analyzer: paste an email or URL, click Analyse, and display a 0–100 heuristic risk score, suspicious indicators, evidence, and recommended actions.

Login Analyzer: synthetic login event table with detection of repeated failures, unfamiliar devices, and suspicious login patterns.

Attack-Chain Explorer: correlate the synthetic phishing email, suspicious link, login failures, and unusual successful login. Display a visual timeline, linked evidence, and an explanation of the risk.

Demo Center: a working Run Account Takeover Scenario button that populates the synthetic events, runs the analysis, and updates the incident timeline and dashboard.

Use the existing stack and dependencies. Use local state and built-in synthetic data; do not require Supabase, authentication, external APIs, paid services, or generated images. Use deterministic detection rules with transparent scoring. Explain uncertainty and never claim that suspicious evidence proves a real attack.

All navigation and buttons must work. Add incident acknowledge, investigate, and resolve actions. Include loading and empty states where appropriate.

Prioritise a working end-to-end demonstration over a landing page. Build all five sections in one pass, avoid unnecessary packages and extra features, and ensure the application compiles and is responsive. Do not ask questions or stop at static mock-ups.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://trusttrace-attack-atlas.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/09d6b8cc-bce1-4323-91de-cca6e451f08b).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
