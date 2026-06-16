package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.openapi.components.service
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory

/** Registers the bottom "Spring Taint" tool window and wires its panel into the service. */
class SpringTaintToolWindowFactory : ToolWindowFactory, DumbAware {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = ResultsPanel(project)
        val service = project.service<SpringTaintService>()
        service.panel = panel
        panel.setFindings(service.findings)
        val content = ContentFactory.getInstance().createContent(panel, "", false)
        toolWindow.contentManager.addContent(content)
    }
}
