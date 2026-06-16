import type { ChangeEvent } from "react";

export function TopBar({
  tool,
  files,
  rules,
  onFile,
}: {
  tool: string;
  files: number;
  rules: number;
  onFile: (f: File) => void;
}) {
  const handle = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) onFile(f);
  };
  return (
    <header className="topbar">
      <div className="brand">
        <svg className="logo" viewBox="0 0 40 40" aria-hidden>
          <path className="logo-flow" d="M8 8 L8 20 Q8 26 14 26 L26 26 Q32 26 32 32" />
          <circle className="logo-src" cx="8" cy="8" r="3.4" />
          <circle className="logo-snk" cx="32" cy="32" r="3.4" />
        </svg>
        <div className="brand-text">
          <span className="brand-name">
            spring<span className="dot">·</span>taint
          </span>
          <span className="brand-sub">taint flow console</span>
        </div>
      </div>

      <div className="scan-meta">
        <Meta k="tool" v={tool} />
        <Meta k="files" v={files} />
        <Meta k="rules" v={rules} />
      </div>

      <label className="load-btn">
        <input type="file" accept=".sarif,.json" hidden onChange={handle} />
        <svg viewBox="0 0 24 24" width={15} height={15} aria-hidden>
          <path d="M12 16V4M7 9l5-5 5 5M5 20h14" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Load SARIF
      </label>
    </header>
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
