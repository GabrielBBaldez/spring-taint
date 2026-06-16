type Mark = "yes" | "no" | "partial";

const ROWS: { scenario: string; same: Mark; st: Mark }[] = [
  { scenario: "Same-method SQL injection (concat in one method)", same: "yes", st: "yes" },
  { scenario: "Cross-layer SQLi (Controller → Service → Repository)", same: "no", st: "yes" },
  { scenario: "Taint via @KafkaListener / @RabbitListener payload", same: "no", st: "yes" },
  { scenario: "Stored / second-order injection (saved, then read back)", same: "no", st: "yes" },
  { scenario: "Reactive WebFlux flow (Mono / Flux wrappers)", same: "no", st: "yes" },
  { scenario: "Near-miss sanitizer (escaping for the wrong context)", same: "partial", st: "yes" },
  { scenario: "Parameterized query (safe — must NOT be flagged)", same: "yes", st: "yes" },
];

const CVES: { cve: string; url: string; cls: string; flow: string }[] = [
  { cve: "CVE-2020-5427 / 5428", url: "https://spring.io/security/cve-2020-5428/", cls: "SQL injection", flow: "Spring Cloud Data Flow / Task — a request-controlled sort column concatenated into the task-execution query." },
  { cve: "CVE-2016-6652", url: "https://spring.io/security/cve-2016-6652/", cls: "SQL injection", flow: "Spring Data JPA — a Sort value from the request reaches the generated SQL (blind SQLi)." },
  { cve: "CVE-2024-54762", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-54762", cls: "SQL injection", flow: "RuoYi (Spring Boot admin) — an authenticated request parameter reaches a query without sanitization." },
  { cve: "CVE-2018-1273", url: "https://nvd.nist.gov/vuln/detail/CVE-2018-1273", cls: "SpEL injection", flow: "Spring Data Commons — a crafted request payload property path evaluated as a SpEL expression." },
];

function Cell({ mark }: { mark: Mark }) {
  const sym = mark === "yes" ? "✓" : mark === "no" ? "✕" : "~";
  return <td className={`mark ${mark}`}>{sym}</td>;
}

export function Catches() {
  return (
    <main className="wrap page">
      <header className="page-head">
        <span className="kicker">what it catches</span>
        <h1>The question isn't "does SonarQube do this?"</h1>
        <p>
          It's <em>"does spring-taint find what generalist tools miss?"</em> The edge isn't beating
          a SAST suite everywhere — it's that a deep focus on Spring surfaces interprocedural flows
          that same-method analysis leaves on the table.
        </p>
      </header>

      <section className="cmp">
        <table>
          <thead>
            <tr>
              <th>Scenario</th>
              <th>Same-method scanners *</th>
              <th>spring-taint</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.scenario}>
                <td className="scn">{r.scenario}</td>
                <Cell mark={r.same} />
                <Cell mark={r.st} />
              </tr>
            ))}
          </tbody>
        </table>
        <p className="cmp-note">
          * Generalist or community-tier static analysis that reasons within a single method.
          spring-taint runs <strong>alongside</strong> SonarQube, not instead of it — they answer
          different questions.
        </p>
      </section>

      <header className="page-head sub">
        <span className="kicker">the shape it finds</span>
        <h2>A flow that crosses three files</h2>
      </header>
      <section className="flowviz">
        <div className="fv-node src">
          <span className="fv-k">source</span>
          <span className="fv-f">UserController</span>
          <span className="fv-d">@RequestParam name</span>
        </div>
        <span className="fv-arrow">→</span>
        <div className="fv-node via">
          <span className="fv-k">propagates</span>
          <span className="fv-f">UserService</span>
          <span className="fv-d">search(name)</span>
        </div>
        <span className="fv-arrow">→</span>
        <div className="fv-node snk">
          <span className="fv-k">sink</span>
          <span className="fv-f">UserRepository</span>
          <span className="fv-d">jdbc.query("… '" + name + "'")</span>
        </div>
      </section>

      <header className="page-head sub">
        <span className="kicker">in the wild</span>
        <h2>Real CVEs of the classes it detects</h2>
        <p>
          Public CVEs whose root cause is exactly the source-to-sink flow this tool tracks. It
          reports the interprocedural form when the vulnerable call lives in the analyzed code.
        </p>
      </header>
      <section className="cve-list">
        {CVES.map((c) => (
          <article className="cve" key={c.cve}>
            <div className="cve-top">
              <a href={c.url} target="_blank" rel="noopener noreferrer" className="cve-id">{c.cve}</a>
              <span className="cve-cls">{c.cls}</span>
            </div>
            <p className="cve-flow">{c.flow}</p>
          </article>
        ))}
      </section>
    </main>
  );
}
