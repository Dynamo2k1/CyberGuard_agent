// nvd_scanner.c
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "nvd_scanner.h"

#define API_KEY "d63e9c6e-0dd5-42c3-9c30-96806c9ea561"

// Callback function to handle NVD API response
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((char*)userp)[size * nmemb] = 0; // Null-terminate the response
    return size * nmemb;
}

// Function to perform an audit using the NVD API
void PerformNVDAudit() {
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://services.nvd.nist.gov/rest/json/cves/1.0/");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        char response[1024];
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, "apiKey: " API_KEY);

        // Perform the request and print response
        curl_easy_perform(curl);
        printf("NVD Scan Results: %s\n", response);
        curl_easy_cleanup(curl);

        // Optionally send to Elasticsearch
        SendLogToElastic(response, 0);
    }
}
void CheckBannerVulnerability(const char* banner) {
    CURL* curl = curl_easy_init();
    if (curl) {
        char url[1024];
        snprintf(url, sizeof(url), "https://services.nvd.nist.gov/rest/json/cves/1.0/?keyword=%s", banner);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, "apiKey: " API_KEY);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        char response[2048];
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        curl_easy_perform(curl);
        printf("Vulnerability Results: %s\n", response);

        // Optionally send vulnerability results to Elasticsearch
        // SendVulnerabilityResultsToElastic(response);

        curl_easy_cleanup(curl);
    }
}