package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.search.FilenameIndex
import com.intellij.psi.search.GlobalSearchScope
import com.intellij.ui.ColoredListCellRenderer
import com.intellij.ui.SimpleTextAttributes
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import java.awt.BorderLayout
import java.awt.Color
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.DefaultListModel
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants

/** Bottom tool-window content: the list of findings, double-click to jump to the sink. */
class ResultsPanel(private val project: Project) : JPanel(BorderLayout()) {

    private val model = DefaultListModel<TaintFinding>()
    private val list = JBList(model)
    private val placeholder =
        JLabel("Run Tools > Run Spring Taint Scan to analyze this project.", SwingConstants.CENTER)

    init {
        list.selectionMode = ListSelectionModel.SINGLE_SELECTION
        list.cellRenderer = Renderer()
        list.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) navigate(list.selectedValue)
            }
        })
        showPlaceholder()
    }

    fun setFindings(findings: List<TaintFinding>) {
        model.clear()
        findings.forEach(model::addElement)
        removeAll()
        if (findings.isEmpty()) {
            showPlaceholder()
        } else {
            add(JBScrollPane(list), BorderLayout.CENTER)
        }
        revalidate()
        repaint()
    }

    private fun showPlaceholder() {
        removeAll()
        add(placeholder, BorderLayout.CENTER)
    }

    private fun navigate(f: TaintFinding?) {
        if (f == null) return
        val vf: VirtualFile = ReadAction.compute<VirtualFile?, RuntimeException> {
            FilenameIndex.getVirtualFilesByName(f.file, GlobalSearchScope.projectScope(project)).firstOrNull()
        } ?: return
        OpenFileDescriptor(project, vf, (f.line - 1).coerceAtLeast(0), 0).navigate(true)
    }

    private class Renderer : ColoredListCellRenderer<TaintFinding>() {
        override fun customizeCellRenderer(
            list: JList<out TaintFinding>,
            value: TaintFinding,
            index: Int,
            selected: Boolean,
            hasFocus: Boolean,
        ) {
            append(
                "[${value.severity.uppercase()}] ",
                SimpleTextAttributes(SimpleTextAttributes.STYLE_BOLD, colorFor(value.severity)),
            )
            append(value.ruleId + "  ")
            append("${value.file}:${value.line}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
            if (value.fix != null) {
                append("  autofix", SimpleTextAttributes(SimpleTextAttributes.STYLE_SMALLER, VENOM))
            }
            toolTipText = value.message
        }

        private fun colorFor(sev: String): Color = when (sev.lowercase()) {
            "critical" -> Color(0xFF5468)
            "high" -> Color(0xFFB13D)
            "medium" -> Color(0x4FB6FF)
            else -> Color(0x8A98A8)
        }

        private companion object {
            val VENOM = Color(0x5EF2A0)
        }
    }
}
