package io.github.gabrielbbaldez.springtaint.intellij

import com.google.gson.JsonObject
import com.google.gson.JsonParser

/** A suggested fix attached to a finding (description + unified-style diff). */
data class Fix(val description: String, val diff: String)

/** One finding parsed from the analyzer's SARIF report. */
data class TaintFinding(
    val ruleId: String,
    val severity: String,
    val message: String,
    val file: String,
    val line: Int,
    val confidence: Int?,
    val nearMiss: String?,
    val fix: Fix?,
)

/** Parses the subset of SARIF 2.1 that spring-taint emits. */
object Sarif {

    fun parse(text: String): List<TaintFinding> {
        val root = JsonParser.parseString(text).asJsonObject
        val runs = root.getAsJsonArray("runs") ?: return emptyList()
        if (runs.size() == 0) return emptyList()
        val results = runs[0].asJsonObject.getAsJsonArray("results") ?: return emptyList()

        val out = ArrayList<TaintFinding>(results.size())
        for (element in results) {
            val r = element.asJsonObject
            val props = if (r.has("properties")) r.getAsJsonObject("properties") else null

            val physical = r.getAsJsonArray("locations")
                ?.takeIf { it.size() > 0 }
                ?.get(0)?.asJsonObject
                ?.getAsJsonObject("physicalLocation")
            val artifact = physical?.getAsJsonObject("artifactLocation")
            val region = physical?.getAsJsonObject("region")

            val fixObj = props?.takeIf { it.has("fix") }?.getAsJsonObject("fix")

            out.add(
                TaintFinding(
                    ruleId = str(r, "ruleId") ?: "taint",
                    severity = props?.let { str(it, "severity") } ?: "high",
                    message = r.getAsJsonObject("message")?.let { str(it, "text") } ?: "",
                    file = artifact?.let { str(it, "uri") } ?: "?",
                    line = region?.takeIf { it.has("startLine") }?.get("startLine")?.asInt ?: 0,
                    confidence = props?.takeIf { it.has("confidence") && !it.get("confidence").isJsonNull }
                        ?.get("confidence")?.asInt,
                    nearMiss = props?.let { str(it, "nearMiss") },
                    fix = fixObj?.let { Fix(str(it, "description") ?: "", str(it, "diff") ?: "") },
                ),
            )
        }
        return out
    }

    private fun str(o: JsonObject, key: String): String? =
        if (o.has(key) && !o.get(key).isJsonNull) o.get(key).asString else null
}
