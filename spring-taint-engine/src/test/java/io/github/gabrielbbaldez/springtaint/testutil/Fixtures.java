package io.github.gabrielbbaldez.springtaint.testutil;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Test helpers: write a source/text file under a temp dir, and compile Java sources
 * to bytecode so the ASM-based scanners can run against real {@code .class} files.
 */
public final class Fixtures {

    private Fixtures() {
    }

    /** Writes {@code content} to {@code dir/relativePath}, creating parent dirs. */
    public static Path write(Path dir, String relativePath, String content) throws Exception {
        Path file = dir.resolve(relativePath);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
        return file;
    }

    /**
     * Compiles one source file (named by its fully-qualified class) to a fresh
     * {@code classes} directory under {@code dir}, using the test runtime classpath so
     * fixtures may reference dependencies (SLF4J, …). Returns the classes directory.
     */
    public static Path compile(Path dir, String fqcn, String source) throws Exception {
        Path srcRoot = Files.createDirectories(dir.resolve("src"));
        Path classes = Files.createDirectories(dir.resolve("classes"));
        Path srcFile = srcRoot.resolve(fqcn.replace('.', '/') + ".java");
        Files.createDirectories(srcFile.getParent());
        Files.writeString(srcFile, source);

        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        if (javac == null) {
            throw new IllegalStateException("no system Java compiler (run tests on a JDK)");
        }
        int rc = javac.run(null, null, null,
                "-cp", System.getProperty("java.class.path"),
                "-d", classes.toString(),
                srcFile.toString());
        if (rc != 0) {
            throw new IllegalStateException("fixture failed to compile: " + fqcn);
        }
        return classes;
    }
}
