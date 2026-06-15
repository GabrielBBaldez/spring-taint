package io.github.gabrielbbaldez.springtaint.report.sarif;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Serialises findings to a SARIF 2.1.0 report (consumable by GitHub Advanced
 * Security, GitLab SAST, VS Code, Azure DevOps).
 */
public final class SarifWriter {

    private static final String SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    private static final String TOOL_NAME = "Spring Taint Analyzer";
    private static final String TOOL_VERSION = "0.1.0";
    private static final String TOOL_URI = "https://github.com/GabrielBBaldez/spring-taint";

    private final ObjectMapper mapper = new ObjectMapper();
    private final JsonNodeFactory nf = JsonNodeFactory.instance;

    /** Builds the SARIF document as a pretty-printed JSON string. */
    public String toJson(List<Finding> findings) {
        ObjectNode root = nf.objectNode();
        root.put("$schema", SARIF_SCHEMA);
        root.put("version", "2.1.0");

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", TOOL_NAME);
        driver.put("version", TOOL_VERSION);
        driver.put("informationUri", TOOL_URI);
        driver.set("rules", rules(findings));

        ArrayNode results = run.putArray("results");
        for (Finding f : findings) {
            results.add(result(f));
        }
        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialise SARIF", e);
        }
    }

    /** Writes the SARIF document to {@code out}. */
    public void write(Path out, List<Finding> findings) throws IOException {
        Files.writeString(out, toJson(findings));
    }

    private ArrayNode rules(List<Finding> findings) {
        Set<String> ruleIds = new LinkedHashSet<>();
        for (Finding f : findings) {
            ruleIds.add(f.ruleId());
        }
        ArrayNode rules = nf.arrayNode();
        for (String id : ruleIds) {
            ObjectNode rule = rules.addObject();
            rule.put("id", id);
            rule.putObject("shortDescription").put("text", id);
        }
        return rules;
    }

    private ObjectNode result(Finding f) {
        ObjectNode result = nf.objectNode();
        result.put("ruleId", f.ruleId());
        result.put("level", f.severity().sarifLevel());
        result.putObject("message").put("text", f.message());

        ArrayNode locations = result.putArray("locations");
        FlowStep sink = f.sink();
        if (sink != null) {
            locations.add(location(sink));
        }

        if (!f.flow().isEmpty()) {
            ArrayNode codeFlows = result.putArray("codeFlows");
            ArrayNode threadFlows = codeFlows.addObject().putArray("threadFlows");
            ArrayNode locs = threadFlows.addObject().putArray("locations");
            for (FlowStep step : f.flow()) {
                locs.addObject().set("location", location(step));
            }
        }
        return result;
    }

    private ObjectNode location(FlowStep step) {
        ObjectNode location = nf.objectNode();
        ObjectNode physical = location.putObject("physicalLocation");
        physical.putObject("artifactLocation").put("uri", step.file());
        physical.putObject("region").put("startLine", step.line());
        location.putObject("message").put("text", step.description());
        return location;
    }
}
