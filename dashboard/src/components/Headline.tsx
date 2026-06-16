import { useEffect, useState } from "react";
import { SEV_COLOR, type Severity } from "../lib/sarif";

function useCountUp(target: number, dur = 800) {
  const [n, setN] = useState(0);
  useEffect(() => {
    let raf = 0;
    const t0 = performance.now();
    const step = (t: number) => {
      const p = Math.min((t - t0) / dur, 1);
      setN(Math.round((1 - Math.pow(1 - p, 3)) * target));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, dur]);
  return n;
}

export function Headline({
  total,
  files,
  sevCount,
}: {
  total: number;
  files: number;
  sevCount: Record<Severity, number>;
}) {
  const n = useCountUp(total);
  return (
    <section className="headline">
      <div className="headline-num">{n}</div>
      <div className="headline-side">
        <h1>findings in the analyzed code</h1>
        <p>
          {total
            ? `Interprocedural taint reaching a dangerous sink without a sanitizer, across ${files} files.`
            : "Load a SARIF report to begin — drop a file or use “Load SARIF”."}
        </p>
        <div className="sev-legend">
          {(["critical", "high", "medium"] as Severity[]).map((s) => (
            <span className="lg" key={s}>
              <span className="sw" style={{ background: SEV_COLOR[s] }} />
              {s} · {sevCount[s]}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
