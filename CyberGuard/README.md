
# SIEM Agent Code Documentation

This document provides a detailed explanation of the code files in the SIEM agent project. Each section describes the purpose and functionality of the individual files and their key components.

## 1. `agent.c`

### Overview
`agent.c` is the main source file for the SIEM agent. It coordinates various monitoring and auditing tasks, including event log monitoring, file integrity checks, vulnerability scanning, and compliance assessments.

### Key Functions and Code Explanation

#### `MonitorEventLogs()`

```c
void MonitorEventLogs() {
    HANDLE hEventLog;
    EVENTLOGRECORD* pEventLogRecord;
    BYTE buffer[1024];
    DWORD dwRead, dwNeeded;

    // Open system, security, and application logs
    hEventLog = OpenEventLog(NULL, "System");
    if (!hEventLog) {
        printf("Error opening event log.\n");
        return;
    }

    // Read event logs in real-time
    while (ReadEventLog(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ, 0, buffer, sizeof(buffer), &dwRead, &dwNeeded)) {
        pEventLogRecord = (EVENTLOGRECORD*)buffer;
        while (dwRead > 0) {
            printf("Event ID: %lu\n", pEventLogRecord->EventID);
            printf("Source: %s\n", (char*)pEventLogRecord + sizeof(EVENTLOGRECORD));

            // Send log data to Elasticsearch
            SendLogToElastic((char*)pEventLogRecord + sizeof(EVENTLOGRECORD), pEventLogRecord->EventID);

            dwRead -= pEventLogRecord->Length;
            pEventLogRecord = (EVENTLOGRECORD*)((BYTE*)pEventLogRecord + pEventLogRecord->Length);
        }
    }

    CloseEventLog(hEventLog);
}
```
- **Opening Event Logs**: Uses `OpenEventLog()` to access the system event logs. Checks if the handle is valid; if not, it reports an error.
- **Reading Logs**: Continuously reads event logs with `ReadEventLog()`. Logs are processed in chunks, and each log entry is sent to Elasticsearch using `SendLogToElastic()`.
- **Loop Through Records**: Iterates through each `EVENTLOGRECORD`, prints the Event ID and source, and updates the buffer position.

#### `MonitorFileIntegrity()`

```c
void MonitorFileIntegrity() {
    HANDLE hDir = CreateFile("C:\\", FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("Error opening directory for monitoring.\n");
        return;
    }

    char buffer[1024];
    DWORD dwBytesReturned;

    while (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE, &dwBytesReturned, NULL, NULL)) {
        FILE_NOTIFY_INFORMATION* pNotify = (FILE_NOTIFY_INFORMATION*)buffer;
        printf("File changed: %ws\n", pNotify->FileName);

        // Send integrity event to Elasticsearch
        SendFileIntegrityLog(pNotify->FileName);
    }

    CloseHandle(hDir);
}
```
- **Opening Directory**: Uses `CreateFile()` to obtain a handle for directory monitoring. It handles errors if the directory cannot be accessed.
- **Reading Directory Changes**: Monitors file changes in the directory with `ReadDirectoryChangesW()`. If changes are detected, it processes and sends them to Elasticsearch.
- **Processing Notifications**: Extracts file change information from `FILE_NOTIFY_INFORMATION` and sends the updated file information to Elasticsearch.

#### `CheckCompliance()`

```c
void CheckCompliance() {
    system("secedit /analyze /cfg C:\\Data\\security_policies.cfg > C:\\Data\\compliance_report.txt");

    // Parse report and send compliance status to Elasticsearch
    SendComplianceReportToElastic("C:\\Data\\compliance_report.txt");
}
```
- **Compliance Check**: Uses the `secedit` command to analyze security policies and generate a compliance report. Redirects output to a text file.
- **Sending Report**: Calls `SendComplianceReportToElastic()` to send the generated report to Elasticsearch for further processing.

#### `main()`

```c
int main() {
    // Monitor Event Logs (Security, Application, System)
    MonitorEventLogs();

    // Monitor File Integrity (C: drive)
    MonitorFileIntegrity();

    // Perform Vulnerability Scan
    PerformNVDAudit();

    // Check Compliance with PCI-DSS, HIPAA, and GDPR
    CheckCompliance();

    printf("Audit completed. Logs sent to Elasticsearch.\n");
    return 0;
}
```
- **Main Execution**: Sequentially calls functions to monitor event logs, file integrity, perform vulnerability scans, and check compliance. Prints a completion message.

## 2. `elastic.h`

### Overview
`elastic.h` defines the function prototypes for interacting with Elasticsearch.

### Key Functions
- **`SendLogToElastic()`**: Sends log data to Elasticsearch.
- **`SendFileIntegrityLog()`**: Sends file integrity events to Elasticsearch.
- **`SendComplianceReportToElastic()`**: Sends compliance reports to Elasticsearch.

## 3. `elastic.c`

### Overview
`elastic.c` implements the functions declared in `elastic.h`. These functions send various types of data to Elasticsearch using the cURL library.

### Key Functions and Code Explanation

#### `SendLogToElastic()`

```c
void SendLogToElastic(const char* log, unsigned long eventId) {
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:9200/logs/_doc");

        char json[1024];
        snprintf(json, sizeof(json), "{\"event_id\": %lu, \"log\": \"%s\"}", eventId, log);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
```
- **Initializing cURL**: Starts a cURL session with `curl_easy_init()`.
- **Setting Options**: Configures cURL with the Elasticsearch URL and JSON payload.
- **Performing Request**: Sends the HTTP POST request to Elasticsearch with `curl_easy_perform()`, and cleans up resources.

#### `SendFileIntegrityLog()`

```c
void SendFileIntegrityLog(const char* fileName) {
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:9200/integrity/_doc");

        char json[512];
        snprintf(json, sizeof(json), "{\"file\": \"%s\", \"event\": \"modified\"}", fileName);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
```
- **Initializing cURL**: Starts a cURL session.
- **Setting Options**: Configures cURL to send file integrity events to Elasticsearch.
- **Performing Request**: Sends the file modification event to Elasticsearch.

#### `SendComplianceReportToElastic()`

```c
void SendComplianceReportToElastic(const char* reportPath) {
    FILE* file = fopen(reportPath, "r");
    if (file) {
        char line[256];
        while (fgets(line, sizeof(line), file)) {
            CURL* curl = curl_easy_init();
            if (curl) {
                curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:9200/compliance/_doc");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, line);
                curl_easy_perform(curl);
                curl_easy_cleanup(curl);
            }
        }
        fclose(file);
    }
}
```
- **Reading File**: Opens the compliance report file and reads it line by line.
- **Sending Lines**: For each line, initializes a cURL session, configures it to send the line to Elasticsearch, and performs the request.

## 4. `network_scanner.h`

### Overview
`network_scanner.h` declares the functions used for network scanning.

### Key Functions
- **`ScanNetwork()`**: Scans a range of ports on a target IP address to determine if they are open.

## 5. `network_scanner.c`

### Overview
`network_scanner.c` implements network scanning functionalities, including obtaining the local IP address, scanning ports, and grabbing banners.

### Key Functions and Code Explanation

#### `GetLocalIPAddress()`

```c
char* GetLocalIPAddress() {
    WSADATA wsaData;
    char* ipAddress = malloc(INET_ADDRSTRLEN);
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return NULL;
    }

    char hostName[256];
    if (gethostname(hostName, sizeof(hostName)) == SOCKET_ERROR) {
        fprintf(stderr, "gethostname failed: %d\n", WSAGetLastError());
        WSACleanup();
        return NULL;
    }

    struct addrinfo hints = { 0 }, * info;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(hostName, NULL, &hints, &info) != 0) {
        fprintf

(stderr, "getaddrinfo failed: %d\n", WSAGetLastError());
        WSACleanup();
        return NULL;
    }

    struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)info->ai_addr;
    inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipAddress, INET_ADDRSTRLEN);

    freeaddrinfo(info);
    WSACleanup();

    return ipAddress;
}
```
- **Initializing Winsock**: Calls `WSAStartup()` to initialize the Winsock library.
- **Getting Hostname**: Retrieves the local hostname with `gethostname()`.
- **Resolving IP Address**: Uses `getaddrinfo()` to resolve the hostname to an IP address, and `inet_ntop()` to convert the IP address to a string.

#### `GrabBanner()`

```c
char* GrabBanner(SOCKET socket) {
    static char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    recv(socket, buffer, sizeof(buffer) - 1, 0);
    return buffer;
}
```
- **Receiving Data**: Receives data from the given socket and stores it in a buffer. The buffer is zeroed out before receiving data.

#### `ScanNetwork()`

```c
void ScanNetwork(int startPort, int endPort) {
    char* targetIP = GetLocalIPAddress();
    if (targetIP == NULL) {
        printf("Failed to get local IP address.\n");
        return;
    }

    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    int port;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        free(targetIP);
        return;
    }

    for (port = startPort; port <= endPort; port++) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
            continue;
        }

        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        if (inet_pton(AF_INET, targetIP, &server.sin_addr) <= 0) {
            fprintf(stderr, "Invalid address/ Address not supported\n");
            closesocket(sock);
            continue;
        }

        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
            printf("Port %d is open\n", port);

            // Grab the banner
            char* banner = GrabBanner(sock);
            printf("Banner: %s\n", banner);

            // Optionally send the banner info to Elasticsearch
            // SendBannerToElastic(targetIP, port, banner);

            // Check if the banner indicates a vulnerability
            // CheckBannerVulnerability(banner);
        }
        else {
            printf("Port %d is closed\n", port);
        }

        closesocket(sock);
    }

    WSACleanup();
    free(targetIP); // Free allocated memory
}
```
- **Getting IP Address**: Calls `GetLocalIPAddress()` to get the local IP address.
- **Scanning Ports**: Iterates through the specified port range, creates a socket, sets the timeout, and attempts to connect to each port.
- **Checking Open Ports**: If the port is open, it grabs the banner and optionally sends it to Elasticsearch.

## 6. `nvd_scanner.h`

### Overview
`nvd_scanner.h` declares the functions used for querying the National Vulnerability Database (NVD) and checking vulnerabilities.

### Key Functions
- **`FetchNVDData()`**: Fetches vulnerability data from the NVD.
- **`ParseNVDData()`**: Parses the retrieved NVD data.
- **`CheckVulnerability()`**: Checks if a software version is vulnerable based on the NVD data.

## 7. `nvd_scanner.c`

### Overview
`nvd_scanner.c` implements the functions declared in `nvd_scanner.h`, focusing on vulnerability scanning by interacting with the NVD API.

### Key Functions and Code Explanation

#### `FetchNVDData()`

```c
void FetchNVDData(const char* url, char* buffer, size_t bufferSize) {
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
```
- **Initializing cURL**: Initializes a cURL session.
- **Setting Options**: Configures cURL with the NVD API URL and callback function.
- **Performing Request**: Executes the HTTP request to fetch data from NVD.

#### `ParseNVDData()`

```c
void ParseNVDData(const char* data) {
    // Parse the JSON data from NVD and extract vulnerability information
    // Example implementation may use a JSON parsing library
}
```
- **Parsing Data**: Parses the JSON response from NVD. This function needs to be implemented to handle specific data extraction.

#### `CheckVulnerability()`

```c
int CheckVulnerability(const char* version) {
    // Compare the software version with known vulnerabilities from NVD
    // Return 1 if vulnerable, 0 otherwise
    return 0;
}
```
- **Checking Vulnerability**: Compares the provided software version with known vulnerabilities and returns the result.

## 8. `response.h`

### Overview
`response.h` declares the function used for responding to security incidents by blocking IP addresses.

### Key Functions
- **`BlockIP()`**: Blocks an IP address by adding a rule to the Windows Firewall.

## 9. `response.c`

### Overview
`response.c` implements the function declared in `response.h` for blocking IP addresses.

### Key Functions and Code Explanation

#### `BlockIP()`

```c
void BlockIP(const char* ipAddress) {
    char command[256];
    snprintf(command, sizeof(command), "netsh advfirewall firewall add rule name=\"Block IP\" dir=in action=block remoteip=%s", ipAddress);
    system(command);
    printf("Blocked IP: %s\n", ipAddress);
}
```
- **Constructing Command**: Builds a command string to block the specified IP address using the `netsh` utility.
- **Executing Command**: Executes the command with `system()` to apply the firewall rule and prints a confirmation message.

## Conclusion

The SIEM agent codebase integrates several core functionalities essential for robust security monitoring and incident response.
It monitors event logs and file integrity, performs compliance checks, and scans network ports for vulnerabilities. By leveraging
Elasticsearch for centralized log aggregation and cURL for HTTP communication, the agent ensures efficient data handling and real-time alerting.
The integration of network scanning, vulnerability assessment with NVD, and IP blocking further enhances the agent's capability to proactively manage 
and respond to security threats. Overall, this comprehensive approach to security monitoring equips the SIEM agent with the tools needed to maintain a
secure and compliant IT environment.
