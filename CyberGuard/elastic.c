// elastic.c
#include <stdio.h>
#include <curl/curl.h>
#include "elastic.h"

// Function to send log data to Elasticsearch
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

// Function to send file integrity events to Elasticsearch
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

// Function to send compliance report to Elasticsearch
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
