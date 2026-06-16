package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.project.DumbAwareAction

/** Tools > Run Spring Taint Scan. */
class ScanAction : DumbAwareAction() {
    override fun actionPerformed(e: AnActionEvent) {
        e.project?.let { runSpringTaintScan(it) }
    }
}
