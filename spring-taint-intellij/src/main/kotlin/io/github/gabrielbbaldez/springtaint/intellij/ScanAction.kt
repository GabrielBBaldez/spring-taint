package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.DumbAwareAction
import com.intellij.openapi.wm.ToolWindowManager

/** Runs the analyzer on the open project in a background task and shows the findings. */
class ScanAction : DumbAwareAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        ToolWindowManager.getInstance(project).getToolWindow("Spring Taint")?.activate(null)

        object : Task.Backgroundable(project, "Spring Taint analysis", true) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                indicator.text = "Running the analyzer on the compiled classes..."
                val result = SpringTaintRunner.scan(project)
                ApplicationManager.getApplication().invokeLater {
                    project.service<SpringTaintService>().update(result.findings)
                    NotificationGroupManager.getInstance()
                        .getNotificationGroup("Spring Taint")
                        .createNotification(
                            "Spring Taint",
                            result.message,
                            if (result.ok) NotificationType.INFORMATION else NotificationType.WARNING,
                        )
                        .notify(project)
                }
            }
        }.queue()
    }
}
