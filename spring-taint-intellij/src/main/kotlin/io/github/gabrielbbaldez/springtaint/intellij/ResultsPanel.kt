package io.github.gabrielbbaldez.springtaint.intellij

import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.search.FilenameIndex
import com.intellij.psi.search.GlobalSearchScope
import com.intellij.ui.ColoredListCellRenderer
import com.intellij.ui.JBColor
import com.intellij.ui.JBSplitter
import com.intellij.ui.SimpleTextAttributes
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JTextPane
import javax.swing.ListSelectionModel
import javax.swing.text.AttributeSet
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants

private val GREEN = Color(0x57E08A)
private val RED = Color(0xFF7A88)
private val AMBER = Color(0xFFB13D)
private val VENOM = Color(0x5EF2A0)

private fun sevColor(sev: String): Color = when (sev.lowercase()) {
    "critical" -> Color(0xFF5468)
    "high" -> Color(0xFFB13D)
    "medium" -> Color(0x4FB6FF)
    else -> Color(0x8A98A8)
}

private fun fg(color: Color, bold: Boolean = false): AttributeSet =
    SimpleAttributeSet().also {
        StyleConstants.setForeground(it, color)
        if (bold) StyleConstants.setBold(it, true)
    }

/** Tool-window content: findings list on top, a detail pane (flow + suggested-fix diff) below. */
class ResultsPanel(private val project: Project) : JPanel(BorderLayout()) {

    private val model = DefaultListModel<TaintFinding>()
    private val list = JBList(model)
    private val detail = JTextPane().apply { isEditable = false; border = JBUI.Borders.empty(10, 12) }
    private val countLabel = JBLabel("Run Tools > Run Spring Taint Scan to analyze this project.")
    private val applyButton = JButton("Apply all fixes").apply {
        isEnabled = false
        addActionListener { applySpringTaintFixes(project) }
    }
    private var selected: TaintFinding? = null

    init {
        list.selectionMode = ListSelectionModel.SINGLE_SELECTION
        list.cellRenderer = Renderer()
        list.addListSelectionListener { showDetail(list.selectedValue) }
        list.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) navigate(list.selectedValue)
            }
        })

        val rescan = JButton("Re-scan").apply { addActionListener { runSpringTaintScan(project) } }
        val copy = JButton("Copy fix").apply { addActionListener { copyFix() } }
        val header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6)).apply {
            border = JBUI.Borders.customLine(JBColor.border(), 0, 0, 1, 0)
            add(rescan)
            add(applyButton)
            add(copy)
            add(countLabel)
        }

        val splitter = JBSplitter(true, 0.45f).apply {
            firstComponent = JBScrollPane(list)
            secondComponent = JBScrollPane(detail)
        }

        add(header, BorderLayout.NORTH)
        add(splitter, BorderLayout.CENTER)
        showDetail(null)
    }

    fun setFindings(findings: List<TaintFinding>) {
        model.clear()
        findings.forEach(model::addElement)
        val fixable = findings.count { it.fix != null }
        countLabel.text =
            if (findings.isEmpty()) "No findings."
            else "${findings.size} finding(s), $fixable with an automatic fix."
        applyButton.isEnabled = fixable > 0
        if (findings.isNotEmpty()) list.selectedIndex = 0 else showDetail(null)
        revalidate()
        repaint()
    }

    private fun showDetail(f: TaintFinding?) {
        selected = f
        val doc = detail.styledDocument
        doc.remove(0, doc.length)
        val muted = fg(JBColor.GRAY)
        if (f == null) {
            doc.insertString(0, "Select a finding to see its flow and suggested fix.", muted)
            return
        }
        doc.insertString(doc.length, "[${f.severity.uppercase()}] ", fg(sevColor(f.severity), bold = true))
        doc.insertString(doc.length, "${f.ruleId}    ", fg(JBColor.foreground(), bold = true))
        doc.insertString(doc.length, "${f.file}:${f.line}\n", muted)
        doc.insertString(doc.length, "${f.message}\n", fg(JBColor.foreground()))
        if (f.confidence != null) doc.insertString(doc.length, "confidence: ${f.confidence}%\n", muted)
        if (f.nearMiss != null) doc.insertString(doc.length, "\nNear-miss: ${f.nearMiss}\n", fg(AMBER))

        val fix = f.fix
        if (fix != null) {
            doc.insertString(
                doc.length,
                "\nSuggested fix (review before applying): ${fix.description}\n\n",
                fg(JBColor.foreground(), bold = true),
            )
            for (line in fix.diff.trimEnd('\n').split("\n")) {
                val style = when {
                    line.startsWith("  + ") -> fg(GREEN)
                    line.startsWith("  - ") -> fg(RED)
                    else -> muted
                }
                doc.insertString(doc.length, line.removePrefix("  ") + "\n", style)
            }
        } else {
            doc.insertString(
                doc.length,
                "\nNo automatic fix for this finding (only SQL injection and XSS are auto-fixable).\n",
                muted,
            )
        }
        detail.caretPosition = 0
    }

    private fun copyFix() {
        val diff = selected?.fix?.diff ?: return
        val added = diff.split("\n").filter { it.startsWith("  + ") }.joinToString("\n") { it.removePrefix("  + ") }
        if (added.isNotEmpty()) CopyPasteManager.getInstance().setContents(StringSelection(added))
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
            append("[${value.severity.uppercase()}] ", SimpleTextAttributes(SimpleTextAttributes.STYLE_BOLD, sevColor(value.severity)))
            append(value.ruleId + "  ")
            append("${value.file}:${value.line}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
            if (value.fix != null) {
                append("  autofix", SimpleTextAttributes(SimpleTextAttributes.STYLE_SMALLER, VENOM))
            }
            toolTipText = value.message
        }
    }
}
