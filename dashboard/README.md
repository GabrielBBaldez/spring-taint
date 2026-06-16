# spring-taint console

A dashboard for exploring Spring Taint Analyzer results. It reads the analyzer's
**SARIF 2.1** output and shows the severity breakdown, findings by rule, and the
full **source → sink taint flow** for every finding.

Built with **React + Vite + TypeScript**. Hand-built SVG charts (no chart library),
a dark security-console aesthetic, and a venom-green taint-flow visualization.

![dashboard](https://img.shields.io/badge/React-18-149eca) ![vite](https://img.shields.io/badge/Vite-6-646cff) ![ts](https://img.shields.io/badge/TypeScript-5-3178c6)

## Run

```bash
cd dashboard
npm install
npm run dev          # → http://localhost:4321
```

By default it loads [`public/sample.sarif`](public/sample.sarif) — a real scan of
the project's own benchmark (17 findings). **Drop any `.sarif` file** onto the page,
or use the **Load SARIF** button, to view your own report.

## Produce a report to view

```bash
java -jar spring-taint-engine/target/spring-taint-all.jar scan \
  <classes> --libs <classpath> --output report.sarif
```

## Build

```bash
npm run build        # static site in dist/
npm run preview
```

## Structure

```
src/
├── App.tsx                 # state, SARIF loading, filters, drag & drop
├── lib/sarif.ts            # SARIF parsing + severity model
└── components/
    ├── TopBar, Headline, Stats
    ├── SeverityDonut, RuleBars   # SVG charts
    └── Findings                  # list + expandable taint-flow trace
```
