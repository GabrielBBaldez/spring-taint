package io.github.gabrielbbaldez.springtaint.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * {@code spring-taint} command-line entry point.
 */
@Command(
        name = "spring-taint",
        mixinStandardHelpOptions = true,
        version = "spring-taint 0.14.0",
        description = "Interprocedural taint analysis for Spring Boot, built on Tai-e.",
        subcommands = {ScanCommand.class, SecretsCommand.class, ConfigCommand.class,
                MisconfigCommand.class, ValidateConfigCommand.class, SuppressionsCommand.class,
                CommandLine.HelpCommand.class})
public final class SpringTaintCli implements Runnable {

    @Override
    public void run() {
        new CommandLine(this).usage(System.out);
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new SpringTaintCli()).execute(args);
        System.exit(exitCode);
    }
}
