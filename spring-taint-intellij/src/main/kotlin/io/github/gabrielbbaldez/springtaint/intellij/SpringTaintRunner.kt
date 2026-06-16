package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.util.ExecUtil
import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.module.ModuleManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.projectRoots.JavaSdk
import com.intellij.openapi.projectRoots.ProjectJdkTable
import com.intellij.openapi.roots.CompilerModuleExtension
import com.intellij.openapi.roots.ModuleRootManager
import com.intellij.openapi.roots.OrderEnumerator
import java.io.File
import java.nio.file.Files
import java.nio.file.Path

/** Outcome of a scan: parsed findings, a human-readable message, and whether it ran. */
class ScanResult(val findings: List<TaintFinding>, val message: String, val ok: Boolean)

/**
 * Runs the bundled spring-taint analyzer jar as a separate process on the open project's
 * compiled output and parses the SARIF it produces. The taint scan needs a JDK <= 17 (the
 * Tai-e frontend cannot read newer bytecode), discovered among the registered project SDKs.
 */
object SpringTaintRunner {

    @Volatile
    private var cachedJar: Path? = null

    fun scan(project: Project): ScanResult {
        val target = resolveTarget(project)
            ?: return ScanResult(
                emptyList(),
                "No compiled module found -- build the project first (the analyzer reads .class files).",
                false,
            )
        val java = findJavaLE17()
            ?: return ScanResult(
                emptyList(),
                "The taint scan needs a JDK 17 SDK (Tai-e cannot read JDK 21+ bytecode). " +
                    "Register one in File > Project Structure > SDKs.",
                false,
            )

        val jar = extractJar()
        val sarif = Files.createTempFile("spring-taint", ".sarif")
        try {
            val cmd = GeneralCommandLine(java).withParameters(
                buildList {
                    add("-jar"); add(jar.toString())
                    add("scan"); add(target.output)
                    if (target.libs.isNotEmpty()) { add("--libs"); add(target.libs) }
                    if (target.srcRoot != null) { add("--src"); add(target.srcRoot) }
                    add("--output"); add(sarif.toString())
                },
            )
            // The scan exits non-zero when it finds vulnerabilities; that is expected and the
            // SARIF is written regardless, so we read the file instead of trusting the exit code.
            val ran = runCatching { ExecUtil.execAndGetOutput(cmd) }
            if (ran.isFailure) {
                return ScanResult(emptyList(), "Failed to run the analyzer: ${ran.exceptionOrNull()?.message}", false)
            }
            val text = runCatching { Files.readString(sarif) }.getOrNull()
                ?: return ScanResult(emptyList(), "The analyzer produced no report.", false)
            val findings = Sarif.parse(text)
            val msg = if (findings.isEmpty()) "No findings in ${target.moduleName}."
            else "${findings.size} finding(s) in ${target.moduleName}."
            return ScanResult(findings, msg, true)
        } finally {
            runCatching { Files.deleteIfExists(sarif) }
        }
    }

    private data class Target(val moduleName: String, val output: String, val libs: String, val srcRoot: String?)

    /** Resolves the first built module's output dir, dependency classpath and main source root. */
    private fun resolveTarget(project: Project): Target? =
        ReadAction.compute<Target?, RuntimeException> {
            val module = ModuleManager.getInstance(project).modules.firstOrNull {
                CompilerModuleExtension.getInstance(it)?.compilerOutputPath?.exists() == true
            } ?: return@compute null
            val output = CompilerModuleExtension.getInstance(module)!!.compilerOutputPath!!.path
            val libs = OrderEnumerator.orderEntries(module).recursively().withoutSdk().classes()
                .pathsList.pathList.joinToString(File.pathSeparator)
            val roots = ModuleRootManager.getInstance(module).sourceRoots.map { it.path }
            val src = roots.firstOrNull { it.replace('\\', '/').contains("/src/main/") } ?: roots.firstOrNull()
            Target(module.name, output, libs, src)
        }

    /** A registered JDK whose feature version is <= 17, or null. */
    private fun findJavaLE17(): String? {
        for (sdk in ProjectJdkTable.getInstance().allJdks) {
            if (sdk.sdkType !is JavaSdk) continue
            val feature = parseFeature(sdk.versionString ?: continue) ?: continue
            if (feature in 8..17) {
                val home = sdk.homePath ?: continue
                val exe = File(home, "bin/" + if (isWindows()) "java.exe" else "java")
                if (exe.exists()) return exe.path
            }
        }
        return null
    }

    private fun parseFeature(version: String): Int? {
        val m = Regex("(\\d+)(?:\\.(\\d+))?").find(version) ?: return null
        val major = m.groupValues[1].toIntOrNull() ?: return null
        return if (major == 1) m.groupValues[2].toIntOrNull() else major   // "1.8" -> 8
    }

    private fun isWindows(): Boolean = System.getProperty("os.name").lowercase().contains("win")

    /** Extracts the bundled analyzer jar to a temp file (cached) so it can be run as a process. */
    private fun extractJar(): Path {
        cachedJar?.let { if (Files.exists(it)) return it }
        val tmp = Files.createTempFile("spring-taint-all", ".jar")
        val stream = javaClass.getResourceAsStream("/engine/spring-taint-all.jar")
            ?: error("The bundled analyzer jar was not found in the plugin.")
        stream.use { input -> Files.newOutputStream(tmp).use { input.copyTo(it) } }
        tmp.toFile().deleteOnExit()
        cachedJar = tmp
        return tmp
    }
}
