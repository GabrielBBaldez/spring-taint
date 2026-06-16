export type Severity = "critical" | "high" | "medium" | "low";

export interface TraceStep {
  file: string;
  line: number;
  desc: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  trace: TraceStep[];
  confidence?: number;
  nearMiss?: string;
}

export interface ParsedReport {
  tool: string;
  findings: Finding[];
}

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff5468",
  high: "#ffb13d",
  medium: "#4fb6ff",
  low: "#8a98a8",
};

export const SEV_LIST: Severity[] = ["critical", "high", "medium"];

// Fallback severity by rule id, used only for SARIF that lacks `properties.severity`
// (the engine writes the real severity there). Kept complete -- including the pattern
// scanners -- so older reports still colour correctly.
const SEVERITY: Record<string, Severity> = {
  "sql-injection": "critical",
  "jpql-injection": "critical",
  "command-injection": "critical",
  "spel-injection": "critical",
  "jndi-injection": "critical",
  "template-injection": "critical",
  "hardcoded-secret": "critical",
  xss: "high",
  ssrf: "high",
  xxe: "high",
  "path-traversal": "high",
  "insecure-transport": "high",
  "security-disabled": "high",
  "insecure-config": "high",
  "open-redirect": "medium",
  "actuator-exposure": "medium",
  "h2-console-enabled": "medium",
  "log-injection": "low",
};

const ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function severityOf(ruleId: string): Severity {
  return SEVERITY[ruleId] ?? "high";
}

const SEVERITIES: readonly string[] = ["critical", "high", "medium", "low"];

function asSeverity(v: unknown): Severity | undefined {
  return typeof v === "string" && SEVERITIES.includes(v) ? (v as Severity) : undefined;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function readLocation(physical: any): { file: string; line: number } {
  const p = physical ?? {};
  return { file: p.artifactLocation?.uri ?? "?", line: p.region?.startLine ?? 0 };
}

export function parseSarif(data: any): ParsedReport {
  const run = data?.runs?.[0] ?? {};
  const tool: string = run.tool?.driver?.name ?? "spring-taint";
  const results: any[] = run.results ?? [];

  const findings: Finding[] = results.map((res) => {
    const ruleId: string = res.ruleId ?? "taint";
    const props = res.properties ?? {};
    const primary = readLocation(res.locations?.[0]?.physicalLocation);
    const flowLocations = res.codeFlows?.[0]?.threadFlows?.[0]?.locations ?? [];
    const trace: TraceStep[] = flowLocations.map((l: any) => ({
      ...readLocation(l.location?.physicalLocation),
      desc: l.location?.message?.text ?? "",
    }));
    return {
      ruleId,
      // The engine writes the precise severity in properties; fall back to the rule map.
      severity: asSeverity(props.severity) ?? severityOf(ruleId),
      message: res.message?.text ?? "",
      file: primary.file,
      line: primary.line,
      trace,
      confidence: typeof props.confidence === "number" ? props.confidence : undefined,
      nearMiss: typeof props.nearMiss === "string" ? props.nearMiss : undefined,
    };
  });

  findings.sort(
    (a, b) => ORDER[a.severity] - ORDER[b.severity] || a.ruleId.localeCompare(b.ruleId),
  );

  return { tool: tool.replace(/Spring Taint Analyzer/i, "spring-taint"), findings };
}
