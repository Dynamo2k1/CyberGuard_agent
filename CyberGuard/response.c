// response.c
#include <stdio.h>
#include <windows.h>
#include "response.h"

// Function to block an IP address
void BlockIP(const char* ipAddress) {
    char command[256];
    snprintf(command, sizeof(command), "netsh advfirewall firewall add rule name=\"Block IP\" dir=in action=block remoteip=%s", ipAddress);
    system(command);
    printf("Blocked IP: %s\n", ipAddress);
}
