import type { CSSProperties } from "react";
import { SEV_COLOR, type Severity } from "../lib/sarif";

export function Stats({
  total,
  sevCount,
  files,
  rules,
}: {
  total: number;
  sevCount: Record<Severity, number>;
  files: number;
  rules: number;
}) {
  const cards = [
    { num: total, lbl: "total findings", c: "var(--venom)" },
    { num: sevCount.critical, lbl: "critical", c: SEV_COLOR.critical },
    { num: sevCount.high, lbl: "high", c: SEV_COLOR.high },
    { num: sevCount.medium, lbl: "medium", c: SEV_COLOR.medium },
    { num: files, lbl: "files", c: "var(--text)" },
    { num: rules, lbl: "rules", c: "var(--text)" },
  ];
  return (
    <section className="stats">
      {cards.map((card, i) => (
        <div
          className="stat reveal"
          key={card.lbl}
          style={{ "--accent": card.c, animationDelay: `${0.05 * i}s` } as CSSProperties}
        >
          <div className="num">{card.num}</div>
          <div className="lbl">{card.lbl}</div>
        </div>
      ))}
    </section>
  );
}
