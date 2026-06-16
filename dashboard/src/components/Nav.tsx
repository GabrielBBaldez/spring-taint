import type { Route } from "../lib/useHashRoute";

const LINKS: { id: Route; label: string }[] = [
  { id: "home", label: "home" },
  { id: "dashboard", label: "dashboard" },
  { id: "catches", label: "what it catches" },
  { id: "coverage", label: "coverage" },
];

export function Nav({ route }: { route: Route }) {
  return (
    <header className="nav">
      <a className="brand" href="#/home" aria-label="spring-taint home">
        <img className="logo" src="logo.png" alt="" width={34} height={34} />
        <span className="brand-name">
          spring<span className="dot">·</span>taint
        </span>
      </a>

      <nav className="nav-links">
        {LINKS.map((l) => (
          <a key={l.id} href={`#/${l.id}`} className={route === l.id ? "active" : ""}>
            {l.label}
          </a>
        ))}
      </nav>

      <div className="nav-cta">
        <a
          href="https://github.com/marketplace/actions/spring-taint-analysis"
          target="_blank"
          rel="noopener noreferrer"
        >
          Marketplace
        </a>
        <a
          className="nav-gh"
          href="https://github.com/GabrielBBaldez/spring-taint"
          target="_blank"
          rel="noopener noreferrer"
        >
          GitHub
        </a>
      </div>
    </header>
  );
}
