package io.github.gabrielbbaldez.springtaint.autofix;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParserConfiguration.LanguageLevel;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.printer.lexicalpreservation.LexicalPreservingPrinter;
import io.github.gabrielbbaldez.springtaint.report.Finding;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Generates a parameterized-query fix for a SQL-injection finding by rewriting the
 * source: the concatenated query becomes a {@code ?}-placeholder string and the
 * interpolated values become bound parameters.
 *
 * <pre>{@code
 * jdbc.update("DELETE FROM users WHERE id = " + id);
 * // becomes
 * jdbc.update("DELETE FROM users WHERE id = ?", id);
 * }</pre>
 *
 * <p>Scope, by design: only JdbcTemplate {@code query}/{@code update}/{@code execute}
 * whose query argument (directly, or via a local variable) is a string concatenation.
 * Everything else is left untouched, so a fix is never wrong by guessing.
 */
public final class AutofixGenerator {

    private static final Set<String> JDBC_SINKS = Set.of("query", "update", "execute");
    private static final Set<String> WRITE_SINKS = Set.of("write", "print", "println");
    private static final String HTML_UTILS = "org.springframework.web.util.HtmlUtils";

    public List<Patch> generate(List<Finding> findings, Path srcDir) throws IOException {
        Map<String, Path> sources = indexSources(srcDir);
        List<Patch> patches = new ArrayList<>();
        for (Finding f : findings) {
            Path file = sources.get(f.file());
            if (file == null) {
                continue;
            }
            Optional<Patch> patch = switch (f.ruleId()) {
                case "sql-injection" -> generateSql(f, file);
                case "xss" -> generateXss(f, file);
                default -> Optional.empty();
            };
            patch.ifPresent(patches::add);
        }
        return patches;
    }

    /** Parses {@code file}, set up for minimal-diff lexical preservation. */
    private static CompilationUnit parse(String source) {
        try {
            CompilationUnit cu = new JavaParser(new ParserConfiguration()
                    .setLanguageLevel(LanguageLevel.JAVA_17)).parse(source).getResult().orElse(null);
            if (cu != null) {
                LexicalPreservingPrinter.setup(cu);
            }
            return cu;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Rewrites a concatenated JDBC query into a parameterized one. */
    private Optional<Patch> generateSql(Finding f, Path file) throws IOException {
        String source = Files.readString(file);
        CompilationUnit cu = parse(source);
        if (cu == null) {
            return Optional.empty();
        }
        MethodCallExpr sink = findSink(cu, f.line(), JDBC_SINKS);
        if (sink == null || sink.getArguments().isEmpty()) {
            return Optional.empty();
        }
        BinaryExpr concat = resolveConcat(sink.getArgument(0), sink);
        if (concat == null) {
            return Optional.empty();
        }
        List<Expression> operands = new ArrayList<>();
        flatten(concat, operands);
        List<Expression> params = new ArrayList<>();
        String parameterized = parameterize(operands, params);
        if (params.isEmpty()) {
            return Optional.empty();   // nothing interpolated — not actually injectable
        }
        concat.replace(new StringLiteralExpr(parameterized));
        if (sink.getNameAsString().equals("execute")) {
            sink.setName("update");   // execute(String) has no parameter overload; update(String, Object...) does
        }
        for (Expression p : params) {
            sink.addArgument(p.clone());
        }
        String description = "use a parameterized query (" + params.size() + " bound parameter"
                + (params.size() == 1 ? "" : "s") + ")";
        return patch(f, file, source, cu, description);
    }

    /** Wraps the interpolated values written to the response in HtmlUtils.htmlEscape(). */
    private Optional<Patch> generateXss(Finding f, Path file) throws IOException {
        String source = Files.readString(file);
        CompilationUnit cu = parse(source);
        if (cu == null) {
            return Optional.empty();
        }
        MethodCallExpr sink = findSink(cu, f.line(), WRITE_SINKS);
        if (sink == null || sink.getArguments().isEmpty()) {
            return Optional.empty();
        }
        BinaryExpr concat = resolveConcat(sink.getArgument(0), sink);
        if (concat == null) {
            return Optional.empty();
        }
        List<Expression> operands = new ArrayList<>();
        flatten(concat, operands);
        int escaped = 0;
        for (Expression op : operands) {
            if (!(op instanceof StringLiteralExpr)) {
                op.replace(new MethodCallExpr(new NameExpr("HtmlUtils"), "htmlEscape",
                        new NodeList<>(op.clone())));
                escaped++;
            }
        }
        if (escaped == 0) {
            return Optional.empty();
        }
        if (cu.getImports().stream().noneMatch(i -> i.getNameAsString().equals(HTML_UTILS))) {
            cu.addImport(HTML_UTILS);
        }
        return patch(f, file, source, cu, "escape output with HtmlUtils.htmlEscape ("
                + escaped + " value" + (escaped == 1 ? "" : "s") + ")");
    }

    private static Optional<Patch> patch(Finding f, Path file, String oldSource,
                                         CompilationUnit cu, String description) {
        String newSource = LexicalPreservingPrinter.print(cu);
        boolean highConfidence = f.flow().size() <= 2;   // source and sink in one method, no hops
        return Optional.of(new Patch(file, f.line(), f.ruleId(), description,
                diff(oldSource, newSource), newSource, highConfidence));
    }

    /** The sink call (by name) on or nearest the finding line. */
    private static MethodCallExpr findSink(CompilationUnit cu, int line, Set<String> names) {
        MethodCallExpr best = null;
        int bestDelta = Integer.MAX_VALUE;
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!names.contains(call.getNameAsString()) || call.getArguments().isEmpty()) {
                continue;
            }
            int callLine = call.getBegin().map(p -> p.line).orElse(-1);
            int delta = Math.abs(callLine - line);
            if (delta < bestDelta && delta <= 2) {
                best = call;
                bestDelta = delta;
            }
        }
        return best;
    }

    /**
     * The concatenation behind the query argument, directly or via a local variable.
     * The variable lookup is scoped to the sink's own method, so a same-named variable
     * in another method cannot be picked by mistake.
     */
    private static BinaryExpr resolveConcat(Expression arg, MethodCallExpr sink) {
        if (arg instanceof BinaryExpr be && be.getOperator() == BinaryExpr.Operator.PLUS) {
            return be;
        }
        if (arg instanceof NameExpr name) {
            List<VariableDeclarator> scope = sink.findAncestor(MethodDeclaration.class)
                    .map(m -> m.findAll(VariableDeclarator.class))
                    .orElse(List.of());
            return scope.stream()
                    .filter(v -> v.getNameAsString().equals(name.getNameAsString()))
                    .map(v -> v.getInitializer().orElse(null))
                    .filter(init -> init instanceof BinaryExpr be
                            && be.getOperator() == BinaryExpr.Operator.PLUS)
                    .map(init -> (BinaryExpr) init)
                    .findFirst().orElse(null);
        }
        return null;
    }

    private static void flatten(Expression expr, List<Expression> out) {
        if (expr instanceof BinaryExpr be && be.getOperator() == BinaryExpr.Operator.PLUS) {
            flatten(be.getLeft(), out);
            flatten(be.getRight(), out);
        } else {
            out.add(expr);
        }
    }

    /**
     * Builds the parameterized SQL and collects the bound parameters. A value wrapped
     * in single quotes in the original ({@code '" + name + "'}) becomes a bare
     * {@code ?} — the surrounding quotes are dropped.
     */
    private static String parameterize(List<Expression> operands, List<Expression> params) {
        StringBuilder sql = new StringBuilder();
        boolean stripNextLeadingQuote = false;
        for (int i = 0; i < operands.size(); i++) {
            Expression op = operands.get(i);
            if (op instanceof StringLiteralExpr lit) {
                String value = lit.getValue();
                if (stripNextLeadingQuote && value.startsWith("'")) {
                    value = value.substring(1);
                    stripNextLeadingQuote = false;
                }
                sql.append(value);
            } else {
                boolean precedingQuote = sql.length() > 0 && sql.charAt(sql.length() - 1) == '\'';
                boolean followingQuote = i + 1 < operands.size()
                        && operands.get(i + 1) instanceof StringLiteralExpr next
                        && next.getValue().startsWith("'");
                if (precedingQuote && followingQuote) {
                    sql.setLength(sql.length() - 1);
                    stripNextLeadingQuote = true;
                }
                sql.append('?');
                params.add(op);
            }
        }
        return sql.toString();
    }

    /**
     * A minimal line diff (LCS-based): emits only the lines that actually changed,
     * collapsing unchanged runs to a {@code ...} marker. A naive prefix/suffix trim
     * would bracket the whole region between two distant edits (e.g. an added import
     * at the top and a rewritten line at the bottom), dumping the entire class.
     */
    private static String diff(String oldSource, String newSource) {
        String[] a = oldSource.split("\n", -1);
        String[] b = newSource.split("\n", -1);
        int n = a.length;
        int m = b.length;
        int[][] lcs = new int[n + 1][m + 1];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                lcs[i][j] = a[i].equals(b[j])
                        ? lcs[i + 1][j + 1] + 1
                        : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
            }
        }
        StringBuilder out = new StringBuilder();
        int i = 0;
        int j = 0;
        boolean sawChange = false;
        boolean gap = false;
        while (i < n || j < m) {
            if (i < n && j < m && a[i].equals(b[j])) {
                if (sawChange) {
                    gap = true;   // an unchanged line between edits -> collapse to "..."
                }
                i++;
                j++;
            } else if (j >= m || (i < n && lcs[i + 1][j] >= lcs[i][j + 1])) {
                if (gap) {
                    out.append("  ...\n");
                    gap = false;
                }
                out.append("  - ").append(a[i++].stripTrailing()).append('\n');
                sawChange = true;
            } else {
                if (gap) {
                    out.append("  ...\n");
                    gap = false;
                }
                out.append("  + ").append(b[j++].stripTrailing()).append('\n');
                sawChange = true;
            }
        }
        return out.toString();
    }

    private static Map<String, Path> indexSources(Path srcDir) throws IOException {
        Map<String, Path> out = new LinkedHashMap<>();
        if (Files.isRegularFile(srcDir)) {
            out.put(srcDir.getFileName().toString(), srcDir);
            return out;
        }
        if (Files.isDirectory(srcDir)) {
            Set<String> ambiguous = new HashSet<>();
            try (Stream<Path> paths = Files.walk(srcDir)) {
                for (Path p : (Iterable<Path>) paths
                        .filter(f -> f.toString().endsWith(".java"))::iterator) {
                    String name = p.getFileName().toString();
                    if (out.putIfAbsent(name, p) != null) {
                        ambiguous.add(name);   // same file name in two packages — can't safely rewrite
                    }
                }
            }
            ambiguous.forEach(out::remove);
        }
        return out;
    }
}
