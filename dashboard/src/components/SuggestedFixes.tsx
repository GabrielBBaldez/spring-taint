import { useState, type CSSProperties } from "react";
import { SEV_COLOR, type Finding } from "../lib/sarif";
import { FixDiff } from "./FixDiff";

/** Fallback when the async Clipboard API is unavailable (non-HTTPS context, old browser). */
function legacyCopy(text: string, done: () => void) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    done();
  } catch {
    /* clipboard genuinely unavailable; nothing more we can do */
  }
}

/** Front-and-centre panel: every finding the analyzer can auto-fix, shown as a review card. */
export function SuggestedFixes({ findings }: { findings: Finding[] }) {
  const fixable = findings.filter((f) => f.fix);
  if (!fixable.length) return null;
  return (
    <section className="fixes-panel">
      <div className="fixes-head">
        <h2>
          suggested fixes <span className="count">{fixable.length}</span>
        </h2>
        <span className="fixes-sub">generated patches — review and copy</span>
      </div>
      <div className="fixes-list">
        {fixable.map((f, i) => (
          <FixCard key={`${f.ruleId}-${f.file}-${f.line}-${i}`} finding={f} />
        ))}
      </div>
    </section>
  );
}

function FixCard({ finding }: { finding: Finding }) {
  const [copied, setCopied] = useState(false);
  const added = finding
    .fix!.diff.split("\n")
    .filter((l) => l.startsWith("  + "))
    .map((l) => l.replace(/^ {2}\+ /, ""))
    .join("\n");

  const copy = () => {
    if (!added) return;
    const done = () => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    };
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(added).then(done, () => legacyCopy(added, done));
    } else {
      legacyCopy(added, done);
    }
  };

  return (
    <article className="fixcard" style={{ "--c": SEV_COLOR[finding.severity] } as CSSProperties}>
      <div className="fixcard-head">
        <span className="fixcard-dot" />
        <span className="fixcard-rule">{finding.ruleId}</span>
        <span className="fixcard-loc">
          {finding.file}:{finding.line}
        </span>
        <button className="copy-btn" onClick={copy} type="button">
          {copied ? "copied ✓" : "copy fix"}
        </button>
      </div>
      <div className="fixcard-desc">{finding.fix!.description}</div>
      <FixDiff diff={finding.fix!.diff} />
    </article>
  );
}
