package pqcli;

import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
    name = "pqcli",
    description = "Easy to use command line interface for Bouncy Castle for PQC certificate operations",
    mixinStandardHelpOptions = true,
    version = "PQCLI 0.1.0",
    subcommands = {
        CertificateGenerator.class,
        KeyGenerator.class,
        ViewCommand.class,
        VerifyCommand.class,
        CSRCommand.class,
        SignCommand.class
    })
public class PqCliCommand implements Callable<Integer> {

    // Set at class-init time — before main() runs, after JVM loads this class.
    // Referenced by ProviderSetup and all command classes for delta timestamps.
    static final long T0 = System.nanoTime();
    static final boolean TIMING = System.getenv("PQCLI_TIMING_DEBUG") != null;

    static void t(String label) {
        if (TIMING) {
            long ms = (System.nanoTime() - T0) / 1_000_000L;
            System.err.printf("[TIMING] %-45s +%d ms%n", label, ms);
        }
    }

    @Override
    public Integer call() {
        t("PqCliCommand.call() entered (no subcommand)");
        System.out.println("\r\n" + // ASCII Art
                           "   /\\   \r\n" +   //    /\
                           " /\\\\//\\ \r\n" + //  /\\//\
                           "|\\/ .\\/|\r\n" +  // |\/ .\/|
                           "| <||  |\r\n");    // | <||  |

        System.out.println("Please specify a command!");
        t("PqCliCommand.call() returning");
        return 0;
    }

    public static void main(String[] args) {
        t("main() entry");
        CommandLine cmd = new CommandLine(new PqCliCommand());
        t("CommandLine constructed (all subcommands loaded)");
        int exitCode = cmd.execute(args);
        t("execute() returned");
        System.exit(exitCode);
    }
}
