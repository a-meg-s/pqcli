package pqcli;

import java.security.*;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class ProviderSetup {
    public static int setupProvider() {
        PqCliCommand.t("setupProvider() entered");
        try {
            Security.addProvider(new BouncyCastleProvider());
            PqCliCommand.t("BC provider registered");
            Security.addProvider(new BouncyCastlePQCProvider());
            PqCliCommand.t("BCPQC provider registered");

            Provider provider = Security.getProvider("BCPQC");
            if (provider == null) {
                System.err.println("Error: BCPQC Provider not available!");
                return 1;
            }
        }
        catch (Exception e) {
            System.err.println("Error during provider initialization: " + e.getMessage());
            return 1;
        }
        return 0;
    }
}
