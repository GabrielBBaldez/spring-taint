package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory
import javax.swing.JLabel

/**
 * Bottom tool window that will host the scan results. For now it shows a hint; the
 * results table and click-to-navigate are wired in the next iteration.
 */
class SpringTaintToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = JLabel("Run Tools > Run Spring Taint Scan to analyze this project.")
        val content = ContentFactory.getInstance().createContent(panel, "", false)
        toolWindow.contentManager.addContent(content)
    }
}
