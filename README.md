# OpenTelemetry Log AI

## Project Description
The project is aimed at processing logs and telemetry from over 1000 hosts (Windows and Linux) using the OpenTelemetry service. Logs are collected through the Signoz log processing server, which leverages the OpenTelemetry Collector and sends data to the ClickHouse database.

### Business Objective
The primary goal of the project is to create a service that can analyze logs in real-time:
- Scan logs stored in ClickHouse.
- Interpret the content of these logs and identify potentially dangerous patterns.
- If hazardous logs are detected, send an alert to the Keep service via webhook.

It also plans to utilize pre-defined rules and patterns from the [Sigma Rules](https://github.com/SigmaHQ/sigma) project.

## Architecture
The project follows a modular architecture:

1. **Log Collection:**
   - OpenTelemetry is used for collecting telemetry and logs from Windows and Linux servers.
   - The installed OpenTelemetry Collector forwards data to the Signoz processing server.

2. **Data Storage:**
   - Logs and telemetry are aggregated and stored in a ClickHouse database for subsequent processing.

3. **Log Analysis:**
   - Logs from the database are processed using a processor that:
     - Maps rules from Sigma Rules to the OpenTelemetry standard.
     - Analyzes and processes them based on the defined logic.
   - If necessary, the processing can be converted to the SIEM standard for integration with Sigma Rules interfaces.

4. **Alert System:**
   - When dangerous logs or signatures are decoded, the service:
     - Generates a notification.
     - Sends an alert to the Keep service via webhook integration.

## Potential Next Steps
- Research available open interfaces for using Sigma Rules with SIEM standards.
- Modify the data structure in ClickHouse for SIEM standard integration and automated use of Sigma Rules.
- Optimize the service's performance to handle large volumes of real-time log processing.

## Contribution
Contributors are welcome to join the collaboration. Please refer to the code and documents in this repository for further improvements and adjustments. We are also open to discussing and implementing new ideas!

---
For more information on the project and OpenTelemetry, you can refer to the official documentation.