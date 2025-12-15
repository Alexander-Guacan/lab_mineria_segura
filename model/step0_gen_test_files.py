import os

TEST_DIR = "../tests"
os.makedirs(TEST_DIR, exist_ok=True)

files = {
    # 1. JAVA VULNERABLE
    "VulnerableApp.java": """
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
""",
    # 2. C VULNERABLE
    "vulnerable_prog.c": """
#include <stdio.h>
#include <string.h>

void process_input(char *user_input) {
    char buffer[50];
    // CRITICAL: Buffer Overflow (strcpy)
    strcpy(buffer, user_input);
    
    // CRITICAL: Command Injection
    char cmd[100];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}
""",
    # 3. JAVA SEGURO
    "SafeApp.java": """
public class SafeApp {
    public void runCommand(String[] args) {
        // SAFE: ProcessBuilder with separate args
        ProcessBuilder pb = new ProcessBuilder(args);
    }
}
"""
}

print("Generando archivos de prueba multilenguaje...")
for name, content in files.items():
    with open(os.path.join(TEST_DIR, name), "w") as f:
        f.write(content)
    print(f" -> Creado: {name}")