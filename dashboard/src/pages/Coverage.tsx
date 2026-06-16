import { SEV_COLOR, type Severity } from "../lib/sarif";

const CLASSES: { id: string; cwe: string; sev: Severity; desc: string }[] = [
  { id: "sql-injection", cwe: "CWE-89", sev: "critical", desc: "Untrusted input concatenated into a JDBC / SQL query." },
  { id: "jpql-injection", cwe: "CWE-89", sev: "critical", desc: "Concatenated JPQL passed to EntityManager.createQuery." },
  { id: "command-injection", cwe: "CWE-78", sev: "critical", desc: "User data reaching Runtime.exec / ProcessBuilder." },
  { id: "spel-injection", cwe: "CWE-917", sev: "critical", desc: "User expression parsed by a SpEL ExpressionParser." },
  { id: "jndi-injection", cwe: "CWE-74", sev: "critical", desc: "User-controlled name to InitialContext.lookup (the Log4Shell class)." },
  { id: "template-injection", cwe: "CWE-1336", sev: "critical", desc: "User-controlled template name/body to a template engine (SSTI)." },
  { id: "xss", cwe: "CWE-79", sev: "high", desc: "Untrusted value written to the HTML response without escaping." },
  { id: "ssrf", cwe: "CWE-918", sev: "high", desc: "User-controlled URL fetched by RestTemplate / WebClient." },
  { id: "xxe", cwe: "CWE-611", sev: "high", desc: "External input reaching an unhardened XML parser." },
  { id: "path-traversal", cwe: "CWE-22", sev: "high", desc: "Untrusted filename concatenated into a filesystem path." },
  { id: "open-redirect", cwe: "CWE-601", sev: "medium", desc: "User-controlled redirect target (sendRedirect / view name)." },
  { id: "log-injection", cwe: "CWE-117", sev: "low", desc: "Untrusted value concatenated into a log message." },
];

const FRAMEWORKS: { name: string; inputs: string }[] = [
  { name: "Spring MVC / WebFlux", inputs: "@RequestParam, @PathVariable, @RequestBody, @RequestHeader, @CookieValue, @ModelAttribute, @MatrixVariable, @RequestPart" },
  { name: "Spring Kafka", inputs: "@KafkaListener (payload)" },
  { name: "Spring AMQP / RabbitMQ", inputs: "@RabbitListener (payload)" },
  { name: "JAX-RS / Quarkus", inputs: "@QueryParam, @PathParam, @HeaderParam, @FormParam, @CookieParam" },
  { name: "Micronaut", inputs: "@QueryValue, @PathVariable, @Body, @Header" },
  { name: "Spring Cloud OpenFeign", inputs: "@FeignClient methods returning String (downstream data)" },
  { name: "Servlet / Batch / Upload", inputs: "HttpServletRequest.getParameter/getHeader, MultipartFile.getOriginalFilename, ItemReader.read" },
];

export function Coverage() {
  return (
    <main className="wrap page">
      <header className="page-head">
        <span className="kicker">coverage</span>
        <h1>12 vulnerability classes, 7 framework families</h1>
        <p>
          Taint flows from a framework entry point to a dangerous sink, across methods and
          classes, with sanitizers honoured. Library signatures are recognised in both their{" "}
          <code>jakarta.*</code> (Boot 3) and <code>javax.*</code> (Boot 2) forms.
        </p>
      </header>

      <section className="cards">
        {CLASSES.map((c) => (
          <article className="vc" key={c.id} style={{ ["--c" as string]: SEV_COLOR[c.sev] }}>
            <div className="vc-top">
              <span className="vc-dot" />
              <span className="vc-id">{c.id}</span>
              <span className="vc-cwe">{c.cwe}</span>
            </div>
            <p className="vc-desc">{c.desc}</p>
            <span className="vc-sev">{c.sev}</span>
          </article>
        ))}
      </section>

      <header className="page-head sub">
        <span className="kicker">entry points</span>
        <h2>Where untrusted data enters</h2>
      </header>
      <section className="fw">
        {FRAMEWORKS.map((f) => (
          <div className="fw-row" key={f.name}>
            <span className="fw-name">{f.name}</span>
            <span className="fw-inputs">{f.inputs}</span>
          </div>
        ))}
      </section>

      <section className="trio">
        <div className="panel">
          <div className="panel-head"><h2>sources</h2></div>
          <p className="muted-p">Request parameters, bodies, headers, messaging payloads, uploaded
            file names, downstream-service results, and reads from a <code>@Repository</code>
            (stored / second-order injection).</p>
        </div>
        <div className="panel">
          <div className="panel-head"><h2>sinks</h2></div>
          <p className="muted-p">JdbcTemplate, EntityManager, Statement, Runtime.exec, response
            writers, RestTemplate/WebClient, SpEL parsers, JNDI lookups, XML parsers, template
            engines, redirects. Framework-internal sinks are filtered to avoid false positives.</p>
        </div>
        <div className="panel">
          <div className="panel-head"><h2>sanitizers</h2></div>
          <p className="muted-p">Parameterized queries, <code>HtmlUtils.htmlEscape</code>, bean
            validation, and any method declared in your own YAML config. A <em>near-miss</em> layer
            flags sanitizers that are applied but wrong (e.g. escaping for the wrong context).</p>
        </div>
      </section>

      <p className="page-foot-link">
        Full per-rule reference lives in{" "}
        <a href="https://github.com/GabrielBBaldez/spring-taint/blob/main/docs/rules.md" target="_blank" rel="noopener noreferrer">docs/rules.md</a>.
      </p>
    </main>
  );
}
