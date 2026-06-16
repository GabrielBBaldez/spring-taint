package io.github.gabrielbbaldez.springtaint.secrets;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Scans compiled bytecode for hardcoded secrets — a pattern-based analysis,
 * separate from taint. Detects:
 * <ul>
 *   <li>{@code static final String} constants whose name looks like a secret;</li>
 *   <li>string literals matching known secret formats (AWS keys, private keys, …);</li>
 *   <li>{@code @Value("${prop:default}")} where the default is a hardcoded secret.</li>
 * </ul>
 */
public final class SecretScanner {

    private static final int API = Opcodes.ASM9;
    private static final String VALUE_ANNOTATION = "Lorg/springframework/beans/factory/annotation/Value;";
    private static final String STRING_DESC = "Ljava/lang/String;";

    private static final Pattern SECRET_NAME = Pattern.compile(
            "(?i)(pass(word|wd)?|secret|api[_-]?key|apikey|access[_-]?key|"
            + "private[_-]?key|token|credential|auth)");

    /** High-confidence secret value formats → critical. */
    private static final List<Pattern> SECRET_VALUE = List.of(
            Pattern.compile("AKIA[0-9A-Z]{16}"),                          // AWS access key id
            Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"),        // PEM private key
            Pattern.compile("gh[pousr]_[A-Za-z0-9]{20,}"),               // GitHub token
            Pattern.compile("xox[baprs]-[A-Za-z0-9-]{10,}"),             // Slack token
            Pattern.compile("sk-[A-Za-z0-9]{16,}"));                      // common API secret key

    public List<Finding> scan(Path target) throws IOException {
        List<Finding> findings = new ArrayList<>();
        if (Files.isDirectory(target)) {
            try (Stream<Path> paths = Files.walk(target)) {
                for (Path p : (Iterable<Path>) paths.filter(f -> f.toString().endsWith(".class"))::iterator) {
                    findings.addAll(scanClass(Files.readAllBytes(p)));
                }
            }
        } else if (target.toString().endsWith(".jar")) {
            try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(target))) {
                ZipEntry e;
                while ((e = zip.getNextEntry()) != null) {
                    if (e.getName().endsWith(".class")) {
                        findings.addAll(scanClass(zip.readAllBytes()));
                    }
                }
            }
        } else if (target.toString().endsWith(".class")) {
            findings.addAll(scanClass(Files.readAllBytes(target)));
        }
        return findings;
    }

    private List<Finding> scanClass(byte[] bytecode) {
        List<Finding> out = new ArrayList<>();
        new ClassReader(bytecode).accept(new ClassVisitor(API) {
            String file = "?";

            @Override
            public void visit(int v, int acc, String name, String sig, String sup, String[] ifc) {
                String simple = name.substring(name.lastIndexOf('/') + 1);
                int dollar = simple.indexOf('$');
                file = (dollar >= 0 ? simple.substring(0, dollar) : simple) + ".java";
            }

            @Override
            public FieldVisitor visitField(int access, String name, String desc, String sig, Object value) {
                if (STRING_DESC.equals(desc) && value instanceof String s && !s.isBlank()) {
                    Pattern hit = matchValue(s);
                    if (hit != null) {
                        out.add(secret(Severity.CRITICAL, file,
                                "Hardcoded secret literal in field '" + name + "' (" + mask(s) + ")"));
                    } else if (SECRET_NAME.matcher(name).find()) {
                        out.add(secret(Severity.HIGH, file,
                                "Hardcoded value in secret-named field '" + name + "' (" + mask(s) + ")"));
                    }
                }
                return new FieldVisitor(API) {
                    @Override
                    public AnnotationVisitor visitAnnotation(String adesc, boolean visible) {
                        if (!VALUE_ANNOTATION.equals(adesc)) {
                            return null;
                        }
                        return new AnnotationVisitor(API) {
                            @Override
                            public void visit(String aName, Object aVal) {
                                if ("value".equals(aName) && aVal instanceof String expr) {
                                    checkValueDefault(name, expr, file, out);
                                }
                            }
                        };
                    }
                };
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
                return new MethodVisitor(API) {
                    int line;

                    @Override
                    public void visitLineNumber(int l, Label start) {
                        line = l;
                    }

                    @Override
                    public void visitLdcInsn(Object cst) {
                        if (cst instanceof String s && matchValue(s) != null) {
                            out.add(new Finding("hardcoded-secret", Severity.CRITICAL,
                                    "Hardcoded secret literal (" + mask(s) + ")", null, file, line,
                                    List.of(new FlowStep(file, line, "secret literal in " + name + "()"))));
                        }
                    }
                };
            }
        }, ClassReader.SKIP_FRAMES);
        return out;
    }

    private static void checkValueDefault(String field, String expr, String file, List<Finding> out) {
        // @Value("${prop.name:default}") — flag a hardcoded default that is a secret
        int colon = expr.indexOf(':');
        if (!expr.startsWith("${") || colon < 0) {
            return;
        }
        String prop = expr.substring(2, colon);
        String def = expr.substring(colon + 1, expr.endsWith("}") ? expr.length() - 1 : expr.length());
        if (def.isBlank()) {
            return;
        }
        boolean valueHit = matchValue(def) != null;
        if (valueHit || SECRET_NAME.matcher(prop).find()) {
            out.add(secret(valueHit ? Severity.CRITICAL : Severity.HIGH, file,
                    "Hardcoded default for externalized property '" + prop + "' on field '" + field
                            + "' (" + mask(def) + ")"));
        }
    }

    private static Pattern matchValue(String s) {
        for (Pattern p : SECRET_VALUE) {
            if (p.matcher(s).find()) {
                return p;
            }
        }
        return null;
    }

    private static Finding secret(Severity sev, String file, String message) {
        return new Finding("hardcoded-secret", sev, message, null, file, 0,
                List.of(new FlowStep(file, 0, message)));
    }

    private static String mask(String s) {
        String t = s.strip();
        return t.length() <= 4 ? "***" : t.substring(0, 3) + "***";
    }
}
