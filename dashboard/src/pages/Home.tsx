const PROBLEM = `// Controller
@GetMapping("/users")
List<User> search(@RequestParam String name) {
    return service.search(name);          // tainted
}

// UserRepository.java  (a different file, a layer down)
List<User> find(String name) {
    return jdbc.query(
        "SELECT * FROM users WHERE name = '" + name + "'");  // SQL injection
}`;

const ACTION = `- uses: GabrielBBaldez/spring-taint@v0.17.1
  with:
    path: target/classes
    severity: critical,high`;

const CLI = `java -jar spring-taint-all.jar scan target/classes \\
  --libs "$(cat cp.txt)" --src src/main/java --suggest-fixes`;

const FIX_BEFORE = `jdbc.update("DELETE FROM accounts WHERE owner = '" + owner + "'");`;
const FIX_AFTER = `jdbc.update("DELETE FROM accounts WHERE owner = ?", owner);`;

const FEATURES: { title: string; body: string }[] = [
  {
    title: "Cross-layer by design",
    body: "Real IFDS taint on top of Tai-e — call graph plus pointer analysis, not pattern matching. Flows that cross files and layers are tracked end to end.",
  },
  {
    title: "12 classes · 7 frameworks",
    body: "SQL/JPQL injection, XSS, SSRF, SpEL/JNDI/template injection, path traversal, command injection, open redirect — across Spring MVC, WebFlux, Kafka, RabbitMQ, JAX-RS, Micronaut and OpenFeign.",
  },
  {
    title: "Autofix",
    body: "Generates the parameterized-query (and HTML-escape) patch and applies the safe ones. The dashboard shows the suggested diff per finding.",
  },
  {
    title: "Near-miss sanitizers",
    body: "Flags sanitization that was attempted but is wrong — the most dangerous case, because the developer believes the code is safe.",
  },
  {
    title: "Ships everywhere",
    body: "A CLI, a self-contained jar, a Docker image and a GitHub Action — all emitting SARIF 2.1 for GitHub code scanning.",
  },
  {
    title: "Honest about limits",
    body: "Validated on real open-source apps with zero false positives. The taint scan needs JDK-17 bytecode (a Tai-e frontend limit), documented openly.",
  },
];

export function Home() {
  return (
    <main className="page">
      <section className="hero wrap">
        <img className="hero-logo" src={import.meta.env.BASE_URL + "logo.png"} alt="" width={96} height={96} />
        <h1 className="hero-title">
          spring<span className="dot">·</span>taint
        </h1>
        <p className="hero-tag">Interprocedural taint analysis for Spring Boot, built on Tai-e.</p>
        <p className="hero-sub">
          It follows untrusted data across controllers, services and repositories to a dangerous
          sink — finding multi-layer data-flow vulnerabilities that same-method scanners can't see.
        </p>
        <div className="hero-cta">
          <a className="btn btn-primary" href="#/dashboard">
            Open the dashboard
          </a>
          <a className="btn" href="#/catches">
            What it catches
          </a>
        </div>
        <div className="hero-badges">
          <img src="https://img.shields.io/github/v/release/GabrielBBaldez/spring-taint?sort=semver&color=5ef2a0&labelColor=0b1119&label=release" alt="release" />
          <img src="https://img.shields.io/badge/License-MIT-4fb6ff?labelColor=0b1119" alt="MIT" />
          <img src="https://img.shields.io/badge/Java-17%2B-ffb13d?labelColor=0b1119" alt="Java 17+" />
          <img src="https://img.shields.io/badge/SARIF-2.1-d8e2ec?labelColor=0b1119" alt="SARIF 2.1" />
        </div>
      </section>

      <section className="wrap problem">
        <div className="problem-text">
          <span className="kicker">the problem</span>
          <h2>The vulnerability lives between the layers</h2>
          <p>
            A request parameter flows through a service into a repository and is concatenated into
            SQL. No single method looks wrong, so same-method analysis stays silent — yet
            <code> name = ' OR '1'='1</code> exposes the whole table.
          </p>
        </div>
        <pre className="code">
          <code>{PROBLEM}</code>
        </pre>
      </section>

      <section className="wrap autofix-band">
        <div className="ab-text">
          <span className="kicker">it doesn't just find — it fixes</span>
          <h2>Autofix generates the patch</h2>
          <p>
            For SQL injection and XSS, spring-taint rewrites the vulnerable line into a
            parameterized query or an escaped value. The dashboard shows the diff per finding,
            ready to copy — or apply the safe ones with <code>--fix</code>.
          </p>
        </div>
        <div className="ab-diff">
          <div className="ab-line del">
            <span className="ab-sign">-</span>
            <code>{FIX_BEFORE}</code>
          </div>
          <div className="ab-line add">
            <span className="ab-sign">+</span>
            <code>{FIX_AFTER}</code>
          </div>
        </div>
      </section>

      <section className="wrap feature-grid">
        {FEATURES.map((f) => (
          <article className="feat" key={f.title}>
            <h3>{f.title}</h3>
            <p>{f.body}</p>
          </article>
        ))}
      </section>

      <section className="wrap quickstart">
        <span className="kicker">quickstart</span>
        <h2>Drop it into CI</h2>
        <pre className="code">
          <code>{ACTION}</code>
        </pre>
        <p className="muted-p">Or run the self-contained jar locally (JDK 17 for the taint scan):</p>
        <pre className="code">
          <code>{CLI}</code>
        </pre>
      </section>
    </main>
  );
}
