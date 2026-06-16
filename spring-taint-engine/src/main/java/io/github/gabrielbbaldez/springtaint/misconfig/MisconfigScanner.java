package io.github.gabrielbbaldez.springtaint.misconfig;

import io.github.gabrielbbaldez.springtaint.report.Finding;
import io.github.gabrielbbaldez.springtaint.report.FlowStep;
import io.github.gabrielbbaldez.springtaint.report.Severity;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Scans compiled bytecode for insecure Spring patterns — a pattern-based analysis,
 * separate from taint. Detects:
 * <ul>
 *   <li>{@code csrf().disable()} and {@code frameOptions().disable()} in Spring
 *       Security configuration (CSRF protection / clickjacking defence removed);</li>
 *   <li>{@code @CrossOrigin(origins = "*")} (over-permissive CORS);</li>
 *   <li>{@code Cookie.setHttpOnly(false)} / {@code setSecure(false)};</li>
 *   <li>sensitive values (passwords, tokens, card numbers) passed to a logger.</li>
 * </ul>
 *
 * <p>The Spring Security checks see the lambda DSL ({@code http.csrf(c -> c.disable())})
 * because the lambda body is a synthetic method that is also scanned; the
 * method-reference form ({@code AbstractHttpConfigurer::disable}) compiles to an
 * {@code invokedynamic} and is not matched.
 */
public final class MisconfigScanner {

    private static final int API = Opcodes.ASM9;
    private static final String CROSS_ORIGIN = "Lorg/springframework/web/bind/annotation/CrossOrigin;";

    /** Names of variables/fields/getters whose value should not be logged. */
    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i)(pass(word|wd)?|secret|api[_-]?key|apikey|token|credential|"
            + "card([_-]?number)?|cvv|ssn|cpf|pin|otp)");

    /** Logger types whose message-building calls are sinks for sensitive data. */
    private static final Pattern LOGGER_OWNER = Pattern.compile(
            "org/slf4j/Logger|org/apache/(commons/logging/Log|logging/log4j/Logger)|java/util/logging/Logger");

    private static final Pattern LOG_METHOD = Pattern.compile("trace|debug|info|warn|error|fine|finer|finest|log");

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
            public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
                return crossOriginVisitor(desc, file, out);
            }

            @Override
            public MethodVisitor visitMethod(int acc, String name, String desc, String sig, String[] exc) {
                return new MethodVisitor(API) {
                    int line;
                    boolean lastPushedFalse;
                    boolean sensitiveByValue;          // a sensitive field/getter feeds the current expression
                    final List<Integer> recentAloads = new ArrayList<>();   // ALOAD slots since the last call
                    final List<LogSite> logSites = new ArrayList<>();
                    final java.util.Set<Integer> sensitiveSlots = new java.util.HashSet<>();

                    @Override
                    public AnnotationVisitor visitAnnotation(String adesc, boolean visible) {
                        return crossOriginVisitor(adesc, file, out);
                    }

                    @Override
                    public void visitLineNumber(int l, Label start) {
                        line = l;
                    }

                    @Override
                    public void visitInsn(int opcode) {
                        lastPushedFalse = (opcode == Opcodes.ICONST_0);
                    }

                    @Override
                    public void visitVarInsn(int opcode, int varIndex) {
                        if (opcode == Opcodes.ALOAD) {
                            recentAloads.add(varIndex);
                        } else {
                            lastPushedFalse = false;
                        }
                    }

                    @Override
                    public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                        if ((opcode == Opcodes.GETFIELD || opcode == Opcodes.GETSTATIC)
                                && SENSITIVE.matcher(fname).find()) {
                            sensitiveByValue = true;
                        }
                        lastPushedFalse = false;
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String mName, String mDesc, boolean itf) {
                        // CSRF / clickjacking protection disabled
                        if (mName.equals("disable") && owner.endsWith("CsrfConfigurer")) {
                            out.add(misconfig(Severity.HIGH, file, line,
                                    "CSRF protection disabled (csrf().disable())"));
                        } else if (mName.equals("disable")
                                && (owner.contains("FrameOptions") || owner.endsWith("HeadersConfigurer"))) {
                            out.add(misconfig(Severity.MEDIUM, file, line,
                                    "Clickjacking protection disabled (frameOptions().disable())"));
                        }

                        // Insecure cookie flags: setHttpOnly(false) / setSecure(false)
                        if ((mName.equals("setHttpOnly") || mName.equals("setSecure"))
                                && owner.endsWith("Cookie") && lastPushedFalse) {
                            out.add(misconfig(Severity.MEDIUM, file, line,
                                    "Insecure cookie: " + mName + "(false)"));
                        }

                        boolean isLog = LOGGER_OWNER.matcher(owner).find() && LOG_METHOD.matcher(mName).matches();
                        if (isLog) {
                            // Record the call; sensitive locals are resolved at visitEnd, once the
                            // LocalVariableTable (which carries variable names) has been visited.
                            logSites.add(new LogSite(line, sensitiveByValue, new ArrayList<>(recentAloads)));
                        }
                        // This call consumes the current expression's value. It carries a sensitive
                        // value forward only if it is itself a sensitive getter (e.g. getPassword());
                        // otherwise the prior sensitive value was consumed here (e.g. by encoder.matches)
                        // and must not taint a later, unrelated log call.
                        sensitiveByValue = SENSITIVE.matcher(mName).find()
                                && (mName.startsWith("get") || mName.startsWith("is"));
                        // Arguments are consumed by the call; start a fresh window.
                        recentAloads.clear();
                        lastPushedFalse = false;
                    }

                    @Override
                    public void visitLdcInsn(Object cst) {
                        lastPushedFalse = false;
                    }

                    @Override
                    public void visitLocalVariable(String vName, String vDesc, String vSig,
                                                   Label start, Label end, int index) {
                        if (SENSITIVE.matcher(vName).find()) {
                            sensitiveSlots.add(index);
                        }
                    }

                    @Override
                    public void visitEnd() {
                        for (LogSite site : logSites) {
                            boolean sensitiveLocal = site.aloadSlots().stream().anyMatch(sensitiveSlots::contains);
                            if (site.sensitiveByValue() || sensitiveLocal) {
                                out.add(misconfig(Severity.MEDIUM, file, site.line(),
                                        "Sensitive data passed to a logger (information disclosure)"));
                            }
                        }
                    }
                };
            }
        }, ClassReader.SKIP_FRAMES);
        return out;
    }

    /** Visits a {@code @CrossOrigin} annotation, flagging {@code origins/value = "*"}. */
    private static AnnotationVisitor crossOriginVisitor(String desc, String file, List<Finding> out) {
        if (!CROSS_ORIGIN.equals(desc)) {
            return null;
        }
        return new AnnotationVisitor(API) {
            @Override
            public AnnotationVisitor visitArray(String name) {
                if (!"origins".equals(name) && !"value".equals(name)) {
                    return null;
                }
                return new AnnotationVisitor(API) {
                    @Override
                    public void visit(String n, Object value) {
                        if ("*".equals(value)) {
                            out.add(misconfig(Severity.MEDIUM, file, 0,
                                    "Over-permissive CORS: @CrossOrigin(origins = \"*\")"));
                        }
                    }
                };
            }
        };
    }

    private static Finding misconfig(Severity sev, String file, int line, String message) {
        return new Finding("insecure-config", sev, message, null, file, line,
                List.of(new FlowStep(file, line, message)));
    }

    /** A logger call to be judged once local-variable names are known. */
    private record LogSite(int line, boolean sensitiveByValue, List<Integer> aloadSlots) {
    }
}
