package io.github.gabrielbbaldez.springtaint.autofix;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParserConfiguration.LanguageLevel;
import com.github.javaparser.ast.CompilationUnit;
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

    public List<Patch> generate(List<Finding> findings, Path srcDir) throws IOException {
        Map<String, Path> sources = indexSources(srcDir);
        List<Patch> patches = new ArrayList<>();
        for (Finding f : findings) {
            if (!f.ruleId().equals("sql-injection")) {
                continue;
            }
            Path file = sources.get(f.file());
            if (file != null) {
                generateOne(f, file).ifPresent(patches::add);
            }
        }
        return patches;
    }

    private Optional<Patch> generateOne(Finding f, Path file) throws IOException {
        String source = Files.readString(file);
        CompilationUnit cu;
        try {
            cu = new JavaParser(new ParserConfiguration().setLanguageLevel(LanguageLevel.JAVA_17))
                    .parse(source).getResult().orElse(null);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
        if (cu == null) {
            return Optional.empty();
        }
        LexicalPreservingPrinter.setup(cu);

        MethodCallExpr sink = findSink(cu, f.line());
        if (sink == null || sink.getArguments().isEmpty()) {
            return Optional.empty();
        }
        Expression queryArg = sink.getArgument(0);
        BinaryExpr concat = resolveConcat(queryArg, sink);
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

        String newSource = LexicalPreservingPrinter.print(cu);
        boolean highConfidence = f.flow().size() <= 2;   // source and sink in one method, no hops
        String description = "use a parameterized query (" + params.size() + " bound parameter"
                + (params.size() == 1 ? "" : "s") + ")";
        return Optional.of(new Patch(file, f.line(), f.ruleId(), description,
                diff(source, newSource), newSource, highConfidence));
    }

    /** The JdbcTemplate call on (or nearest below) the sink line. */
    private static MethodCallExpr findSink(CompilationUnit cu, int line) {
        MethodCallExpr best = null;
        int bestDelta = Integer.MAX_VALUE;
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!JDBC_SINKS.contains(call.getNameAsString()) || call.getArguments().isEmpty()) {
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

    /** A minimal unified-style diff of the changed region. */
    private static String diff(String oldSource, String newSource) {
        String[] a = oldSource.split("\n", -1);
        String[] b = newSource.split("\n", -1);
        int start = 0;
        while (start < a.length && start < b.length && a[start].equals(b[start])) {
            start++;
        }
        int endA = a.length - 1;
        int endB = b.length - 1;
        while (endA >= start && endB >= start && a[endA].equals(b[endB])) {
            endA--;
            endB--;
        }
        StringBuilder out = new StringBuilder();
        for (int i = start; i <= endA; i++) {
            out.append("  - ").append(a[i].stripTrailing()).append('\n');   // keep indentation, drop trailing CR
        }
        for (int i = start; i <= endB; i++) {
            out.append("  + ").append(b[i].stripTrailing()).append('\n');
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
