import { useEffect, useState } from "react";
import { SEV_COLOR, type Severity } from "../lib/sarif";

export function RuleBars({
  ruleCount,
  severityOf,
}: {
  ruleCount: Record<string, number>;
  severityOf: (rule: string) => Severity;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(id);
  }, []);

  const entries = Object.entries(ruleCount).sort((a, b) => b[1] - a[1]);
  const max = Math.max(...entries.map((e) => e[1]), 1);

  return (
    <div className="panel panel-wide">
      <div className="panel-head">
        <h2>by rule</h2>
        <span className="panel-tag">CWE class</span>
      </div>
      <div className="bars">
        {entries.map(([rule, n], i) => {
          const c = SEV_COLOR[severityOf(rule)];
          return (
            <div className="bar-row reveal" key={rule} style={{ animationDelay: `${0.04 * i}s` }}>
              <span className="bar-name" title={rule}>
                {rule}
              </span>
              <span className="bar-track">
                <span
                  className="bar-fill"
                  style={{ width: mounted ? `${(n / max) * 100}%` : 0, background: c, color: c }}
                />
              </span>
              <span className="bar-val">{n}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
