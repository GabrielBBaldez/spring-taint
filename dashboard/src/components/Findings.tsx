import { useState, type CSSProperties } from "react";
import { SEV_COLOR, type Finding, type Severity } from "../lib/sarif";
import { FixDiff } from "./FixDiff";

export function Findings({
  findings,
  sevCount,
  sevFilter,
  toggleSev,
  query,
  setQuery,
}: {
  findings: Finding[];
  sevCount: Record<Severity, number>;
  sevFilter: Set<Severity>;
  toggleSev: (s: Severity) => void;
  query: string;
  setQuery: (q: string) => void;
}) {
  const chips = (["critical", "high", "medium"] as Severity[]).filter((s) => sevCount[s] > 0);
  return (
    <section className="findings">
      <div className="findings-head">
        <h2>
          findings <span className="count">{findings.length}</span>
        </h2>
        <div className="filters">
          <div className="sev-chips">
            {chips.map((s) => (
              <span
                key={s}
                className={`chip ${sevFilter.has(s) ? "active" : ""}`}
                style={{ "--c": SEV_COLOR[s] } as CSSProperties}
                role="button"
                tabIndex={0}
                aria-pressed={sevFilter.has(s)}
                onClick={() => toggleSev(s)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    toggleSev(s);
                  }
                }}
              >
                {s}
                <span className="cn">{sevCount[s]}</span>
              </span>
            ))}
          </div>
          <div className="search">
            <svg viewBox="0 0 24 24" width={14} height={14} aria-hidden>
              <circle cx={11} cy={11} r={7} fill="none" stroke="currentColor" strokeWidth={2} />
              <path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth={2} strokeLinecap="round" />
            </svg>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="filter by rule, file, message…"
            />
          </div>
        </div>
      </div>

      {findings.length ? (
        <div className="finding-list">
          {findings.map((f, i) => (
            <FindingRow key={`${f.ruleId}-${f.file}-${f.line}-${i}`} finding={f} index={i} />
          ))}
        </div>
      ) : (
        <div className="empty">No findings match the current filters.</div>
      )}
    </section>
  );
}

function FindingRow({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(false);
  const c = SEV_COLOR[finding.severity];
  const sink = finding.trace[finding.trace.length - 1] ?? { file: finding.file, line: finding.line };
  return (
    <div
      className={`finding reveal ${open ? "open" : ""}`}
      style={{ "--c": c, animationDelay: `${Math.min(index * 0.03, 0.4)}s` } as CSSProperties}
    >
      <div
        className="f-head"
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setOpen((o) => !o);
          }
        }}
      >
        <span className="f-sev">{finding.severity}</span>
        <div className="f-main">
          <div className="f-rule">
            {finding.ruleId}
            {finding.confidence != null && <span className="conf">{finding.confidence}%</span>}
            {finding.fix && <span className="af-badge">autofix</span>}
          </div>
          <div className="f-msg">{finding.message}</div>
        </div>
        <div className="f-loc">
          <b>{sink.file}</b>:{sink.line}
        </div>
        <svg className="f-toggle" viewBox="0 0 24 24" width={16} height={16}>
          <path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <div className="f-body">
        <div>
          {finding.nearMiss && (
            <div className="nearmiss">
              <b>near-miss sanitizer:</b> {finding.nearMiss}
            </div>
          )}
          {finding.fix && <SuggestedFix fix={finding.fix} />}
          <TaintFlow finding={finding} />
        </div>
      </div>
    </div>
  );
}

function SuggestedFix({ fix }: { fix: { description: string; diff: string } }) {
  return (
    <div className="fix">
      <div className="fix-head">
        <span className="fix-tag">suggested fix</span>
        {fix.description}
      </div>
      <FixDiff diff={fix.diff} />
    </div>
  );
}

function TaintFlow({ finding }: { finding: Finding }) {
  if (!finding.trace.length) return null;
  const n = finding.trace.length;
  return (
    <div className="trace">
      <div className="trace-title">
        taint flow · {n} step{n > 1 ? "s" : ""}
      </div>
      <div className="flow">
        {finding.trace.map((step, i) => {
          const kind = i === 0 ? "src" : i === n - 1 ? "snk" : "via";
          const label = kind === "src" ? "source" : kind === "snk" ? "sink" : "propagates";
          return (
            <div className={`node ${kind}`} key={i}>
              <span className="dot" />
              <div className="body">
                <div className="nk">{label}</div>
                <div className="nfile">
                  {step.file}
                  <span className="ln">:{step.line}</span>
                </div>
                <div className="ndesc">{step.desc}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
