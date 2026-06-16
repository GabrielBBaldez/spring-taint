package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.project.DumbAwareAction
import com.intellij.openapi.ui.Messages

/**
 * Entry-point action for running the analyzer. This first slice only confirms the
 * plugin loads and the action is wired; running the bundled spring-taint jar and
 * rendering the findings comes next.
 */
class ScanAction : DumbAwareAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        Messages.showInfoMessage(
            project,
            "Spring Taint is installed. Running the analyzer and showing findings is wired next.",
            "Spring Taint",
        )
    }
}
