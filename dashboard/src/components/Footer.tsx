export function Footer() {
  return (
    <footer className="foot">
      <span>
        <a
          href="https://github.com/GabrielBBaldez/spring-taint"
          target="_blank"
          rel="noopener noreferrer"
        >
          spring-taint
        </a>{" "}
        · interprocedural taint analysis for Spring Boot · MIT
      </span>
      <span className="foot-tag">built on Tai-e · SARIF 2.1</span>
    </footer>
  );
}
