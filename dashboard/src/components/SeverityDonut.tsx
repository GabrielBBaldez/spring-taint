import { useEffect, useState } from "react";
import { SEV_COLOR, type Severity } from "../lib/sarif";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function SeverityDonut({
  sevCount,
  total,
}: {
  sevCount: Record<Severity, number>;
  total: number;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(id);
  }, []);

  const r = 82;
  const C = 2 * Math.PI * r;
  let offset = 0;
  const segments = ORDER.filter((s) => sevCount[s] > 0).map((s) => {
    const len = total ? (sevCount[s] / total) * C : 0;
    const seg = { s, len, offset };
    offset += len;
    return seg;
  });

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>severity</h2>
        <span className="panel-tag">{total} total</span>
      </div>
      <div className="donut-wrap">
        <svg className="donut" viewBox="0 0 180 180">
          <circle cx={90} cy={90} r={r} fill="none" stroke="#121a23" strokeWidth={16} />
          {segments.map(({ s, len, offset }) => {
            const shown = Math.max(len - 2, 0);
            return (
              <circle
                key={s}
                cx={90}
                cy={90}
                r={r}
                fill="none"
                strokeWidth={16}
                stroke={SEV_COLOR[s]}
                strokeDasharray={mounted ? `${shown} ${C - shown}` : `0 ${C}`}
                strokeDashoffset={-offset}
                style={{ filter: `drop-shadow(0 0 6px ${SEV_COLOR[s]}55)` }}
              />
            );
          })}
        </svg>
        <div className="donut-center">
          <div className="dc-num">{total}</div>
          <div className="dc-lbl">issues</div>
        </div>
      </div>
      <div className="donut-legend">
        {ORDER.filter((s) => sevCount[s] > 0).map((s) => (
          <div className="dl-row" key={s}>
            <span className="sw" style={{ background: SEV_COLOR[s] }} />
            <span className="dl-name">{s}</span>
            <span className="dl-val">{sevCount[s]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
