# Overview

## Project Description

Welcome to my SIEM (Security Information and Event Management) project repository!

I am a cybersecurity student currently working on a comprehensive SIEM solution, and this repository contains the source code for an advanced security agent I have developed. This agent is designed to perform a wide range of security-related tasks and provide detailed system auditing and monitoring.

As a student deeply interested in cybersecurity, my goal with this project is to integrate practical knowledge with advanced security practices to create a robust solution for monitoring and protecting systems.

## Agent Features

The security agent includes the following features:

- **Log Collection**: Collects security, application, and system logs from the operating system.
- **Active Response**: Implements response actions such as IP blocking to mitigate attacks.
- **Network Intrusion Detection**: Monitors network traffic for suspicious activity.
- **System Auditing and Security**:
  - **File Integrity Monitoring**: Monitors file changes on the system.
  - **Log Analysis**: Analyzes collected logs for anomalies.
  - **Rootkit Detection**: Detects potential rootkits.
  - **Configuration Assessment**: Assesses system configurations for vulnerabilities.
  - **Vulnerability Detection**: Identifies known vulnerabilities using the NVD (National Vulnerability Database).
  - **Compliance Monitoring**: Ensures adherence to compliance frameworks such as PCI-DSS, HIPAA, and GDPR.
  - **Incident Detection and Response**: Detects security incidents and responds accordingly.
- **Additional Monitoring**:
  - **Registry Checks**: Monitors the Windows Registry for unauthorized changes.
  - **RAM Usage Checks**: Monitors system RAM usage.

## Technologies Used

- **Programming Language**: C
- **Libraries**: Winsock2 for network operations
- **Backend**: Elasticsearch for log aggregation and analysis
- **API**: National Vulnerability Database (NVD) for vulnerability information

Feel free to explore the code and contribute to the project! As I continue to develop and enhance this solution, I welcome any feedback or contributions that can help improve its functionality and effectiveness in the realm of cybersecurity.
