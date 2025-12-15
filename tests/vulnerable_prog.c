
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
