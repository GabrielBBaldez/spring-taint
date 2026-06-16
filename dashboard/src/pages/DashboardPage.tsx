import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from "react";
import { parseSarif, severityOf, type ParsedReport, type Severity } from "../lib/sarif";
import { Headline } from "../components/Headline";
import { Stats } from "../components/Stats";
import { SeverityDonut } from "../components/SeverityDonut";
import { RuleBars } from "../components/RuleBars";
import { Findings } from "../components/Findings";
import { SuggestedFixes } from "../components/SuggestedFixes";

export function DashboardPage() {
  const [report, setReport] = useState<ParsedReport | null>(null);
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [query, setQuery] = useState("");
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    fetch("sample.sarif")
      .then((r) => r.json())
      .then((d) => setReport(parseSarif(d)))
      .catch(() => setReport({ tool: "spring-taint", findings: [] }));
  }, []);

  const loadFile = useCallback((file: File) => {
    file
      .text()
      .then((t) => setReport(parseSarif(JSON.parse(t))))
      .catch((e) => alert("Could not parse SARIF: " + e.message));
  }, []);

  // drag & drop a SARIF file anywhere on this page
  useEffect(() => {
    let depth = 0;
    const enter = (e: DragEvent) => { e.preventDefault(); if (++depth === 1) setDragging(true); };
    const over = (e: DragEvent) => e.preventDefault();
    const leave = (e: DragEvent) => { e.preventDefault(); if (--depth <= 0) { depth = 0; setDragging(false); } };
    const drop = (e: DragEvent) => {
      e.preventDefault(); depth = 0; setDragging(false);
      const f = e.dataTransfer?.files?.[0]; if (f) loadFile(f);
    };
    window.addEventListener("dragenter", enter);
    window.addEventListener("dragover", over);
    window.addEventListener("dragleave", leave);
    window.addEventListener("drop", drop);
    return () => {
      window.removeEventListener("dragenter", enter);
      window.removeEventListener("dragover", over);
      window.removeEventListener("dragleave", leave);
      window.removeEventListener("drop", drop);
    };
  }, [loadFile]);

  const stats = useMemo(() => {
    const sevCount: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const ruleCount: Record<string, number> = {};
    const ruleSeverity: Record<string, Severity> = {};
    const files = new Set<string>();
    for (const f of report?.findings ?? []) {
      sevCount[f.severity]++;
      ruleCount[f.ruleId] = (ruleCount[f.ruleId] ?? 0) + 1;
      ruleSeverity[f.ruleId] = f.severity;
      files.add(f.file);
    }
    return { sevCount, ruleCount, ruleSeverity, files: files.size, rules: Object.keys(ruleCount).length };
  }, [report]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return (report?.findings ?? []).filter(
      (f) =>
        (sevFilter.size === 0 || sevFilter.has(f.severity)) &&
        (!q || `${f.ruleId} ${f.file} ${f.message}`.toLowerCase().includes(q)),
    );
  }, [report, sevFilter, query]);

  const toggleSev = (s: Severity) =>
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  const total = report?.findings.length ?? 0;
  const onFileInput = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) loadFile(f);
  };

  return (
    <main className="wrap page">
      <div className="scanbar">
        <div className="scan-meta">
          <Meta k="tool" v={report?.tool ?? "—"} />
          <Meta k="files" v={stats.files} />
          <Meta k="rules" v={stats.rules} />
        </div>
        <label className="load-btn">
          <input type="file" accept=".sarif,.json" hidden onChange={onFileInput} />
          <svg viewBox="0 0 24 24" width={15} height={15} aria-hidden>
            <path d="M12 16V4M7 9l5-5 5 5M5 20h14" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Load SARIF
        </label>
      </div>

      <Headline total={total} files={stats.files} sevCount={stats.sevCount} />
      <Stats total={total} sevCount={stats.sevCount} files={stats.files} rules={stats.rules} />

      <SuggestedFixes findings={report?.findings ?? []} />

      <section className="panels">
        <SeverityDonut sevCount={stats.sevCount} total={total} />
        <RuleBars ruleCount={stats.ruleCount} severityOf={(r) => stats.ruleSeverity[r] ?? severityOf(r)} />
      </section>

      <Findings
        findings={filtered}
        sevCount={stats.sevCount}
        sevFilter={sevFilter}
        toggleSev={toggleSev}
        query={query}
        setQuery={setQuery}
      />

      {dragging && (
        <div className="dropzone">
          <div className="dropzone-inner">release to load SARIF</div>
        </div>
      )}
    </main>
  );
}

function Meta({ k, v }: { k: string; v: string | number }) {
  return (
    <div className="meta-item">
      <span className="meta-k">{k}</span>
      <span className="meta-v">{v}</span>
    </div>
  );
}
