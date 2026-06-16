package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.openapi.components.Service

/** Holds the latest findings and the tool-window panel, so the action can refresh the UI. */
@Service(Service.Level.PROJECT)
class SpringTaintService {

    @Volatile
    var findings: List<TaintFinding> = emptyList()

    var panel: ResultsPanel? = null

    fun update(list: List<TaintFinding>) {
        findings = list
        panel?.setFindings(list)
    }
}
