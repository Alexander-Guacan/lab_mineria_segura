
public class SafeApp {
    public void runCommand(String[] args) {
        // SAFE: ProcessBuilder with separate args
        ProcessBuilder pb = new ProcessBuilder(args);
    }
}
