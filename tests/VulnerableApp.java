
import java.io.*;
public class VulnerableApp {
    public void runCommand(String cmd) {
        try {
            // CRITICAL: Command Injection
            Runtime.getRuntime().exec("cmd.exe /c " + cmd);
        } catch (Exception e) {}
    }
    public void hardcoded() {
        // HIGH: Hardcoded Secret
        String password = "SuperSecretPassword123";
    }
}
