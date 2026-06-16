/** Renders a unified-style autofix diff (lines prefixed "  - " / "  + ") with colour. */
export function FixDiff({ diff }: { diff: string }) {
  const lines = diff.replace(/\n+$/, "").split("\n");
  return (
    <pre className="fix-diff">
      {lines.map((l, i) => {
        const kind = l.startsWith("  + ") ? "add" : l.startsWith("  - ") ? "del" : "ctx";
        return (
          <div key={i} className={`dl ${kind}`}>
            {l.replace(/^ {2}/, "")}
          </div>
        );
      })}
    </pre>
  );
}
