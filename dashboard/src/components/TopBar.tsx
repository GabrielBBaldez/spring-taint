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
        <img className="logo" src="logo.png" alt="Spring Taint" width={38} height={38} />
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
