package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import com.intellij.openapi.vfs.VfsUtil
import com.intellij.openapi.wm.ToolWindowManager

private fun notify(project: Project, message: String, ok: Boolean) {
    NotificationGroupManager.getInstance()
        .getNotificationGroup("Spring Taint")
        .createNotification(
            "Spring Taint",
            message,
            if (ok) NotificationType.INFORMATION else NotificationType.WARNING,
        )
        .notify(project)
}

/** Runs the analyzer in the background and pushes the findings into the tool window. */
fun runSpringTaintScan(project: Project) {
    ToolWindowManager.getInstance(project).getToolWindow("Spring Taint")?.activate(null)
    object : Task.Backgroundable(project, "Spring Taint analysis", true) {
        override fun run(indicator: ProgressIndicator) {
            indicator.isIndeterminate = true
            indicator.text = "Running the analyzer on the compiled classes..."
            val result = SpringTaintRunner.scan(project)
            ApplicationManager.getApplication().invokeLater {
                project.service<SpringTaintService>().update(result.findings)
                notify(project, result.message, result.ok)
            }
        }
    }.queue()
}

/** Applies all suggested fixes to the source, refreshes the VFS, and re-scans. */
fun applySpringTaintFixes(project: Project) {
    object : Task.Backgroundable(project, "Applying Spring Taint fixes", true) {
        override fun run(indicator: ProgressIndicator) {
            indicator.isIndeterminate = true
            indicator.text = "Applying suggested fixes..."
            val message = SpringTaintRunner.applyFixes(project)
            project.guessProjectDir()?.let { VfsUtil.markDirtyAndRefresh(false, true, true, it) }
            ApplicationManager.getApplication().invokeLater {
                notify(project, message, true)
                runSpringTaintScan(project)
            }
        }
    }.queue()
}
