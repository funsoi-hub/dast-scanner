# DAST Scanner - Web Application Vulnerability Assessment Tool

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-20.10+-blue.svg)](https://www.docker.com/)
[![OWASP ZAP](https://img.shields.io/badge/OWASP%20ZAP-2.17.0-red.svg)](https://www.zaproxy.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Dynamic Application Security Testing (DAST) tool built on OWASP ZAP. Automates web application vulnerability scanning with professional VAPT reporting.

## Features

- Automated Vulnerability Scanning - SQLi, XSS, CSRF, security headers, and more
- Professional VAPT Reports - HTML and JSON output with executive summary
- Vulnerability Deduplication - Groups identical findings across URLs
- Docker Containerization - Consistent execution across any platform
- Persistent ZAP Container - Faster repeat scans
- CVSS v3.1 Scoring - Industry-standard severity ratings
- Clickable Table of Contents - Easy report navigation

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      DOCKER ENVIRONMENT                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐     ┌─────────────────┐                 │
│  │  ZAP Container  │     │ Scanner Container│                │
│  │  (Persistent)   │◄────│  (Ephemeral)    │                 │
│  │  Port: 8081     │     │  Runs per scan  │                 │
│  └─────────────────┘     └─────────────────┘                 │
│           │                       │                          │
│           ▼                       ▼                          │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              SHARED VOLUME: /reports/               │     │
│  └─────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker Desktop 20.10+ or Docker Engine
- 8GB RAM recommended
- Git

### Installation

Clone the repository and start the services:

git clone https://github.com/YOUR_USERNAME/dast-scanner-public.git
cd dast-scanner-public
docker compose up -d zap
docker compose build scanner

### Usage

Run a basic scan:

docker compose run --rm scanner --url https://example.com

Run with custom timeout of 4 hours:

docker compose run --rm scanner --url https://example.com --active-timeout 14400

Use a custom scan ID for tracking:

docker compose run --rm scanner --url https://example.com --scan-id "Q1-2026-ASSESSMENT"

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| --url | Target URL to scan | Required |
| --active-timeout | Max scan duration in seconds | 7200 |
| --scan-id | Custom scan identifier | Auto-generated |
| --zap-host | ZAP API host | localhost |
| --zap-port | ZAP API port | 8080 |

## Report Output

Reports are generated in the reports directory with naming format DSCAN-XXX_YYYYMMDD_HHMMSS.html and corresponding JSON files.

### Report Sections
- Confidentiality Statement and Disclaimer
- Assessment Overview based on NIST SP 800-115 and OWASP
- Finding Severity Ratings with CVSS v3.1 scoring
- Risk Explanation covering Likelihood and Impact
- Executive Summary with visual severity cards
- Testing Summary by vulnerability category
- Tester Notes and Recommendations
- Detailed findings with evidence and remediation steps

## Scan Phases and Timing

| Phase | Progress | Activity | Typical Duration |
|-------|----------|----------|------------------|
| Spider Discovery | 0-36% | URL enumeration and passive analysis | 5-10 minutes |
| Active Attacks | 36-37% | SQLi, XSS, CSRF probes | 20-40 minutes |
| Completion | 37-100% | Remaining checks and alert processing | 10-20 minutes |

Note that the 36 to 37 percent phase may appear stalled. This is normal behavior as ZAP sends hundreds of test payloads to each discovered parameter. Do not interrupt the scan during this phase.

## Project Structure

```
dast-scanner-public/
├── dast_scanner.py          # Main scanner application
├── docker-compose.yml       # Docker services configuration
├── Dockerfile               # Scanner container build
├── requirements.txt         # Python dependencies
├── LICENSE                  # MIT License
└── README.md                # This file
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| ZAP container fails to start | Increase Docker memory to at least 4GB in Docker Desktop settings |
| Scan stalls at 36-37% | This is normal. Wait 20-40 minutes for active attack phase to complete |
| No URLs discovered | Target may be a single page application or has no crawlable links. Verify target accessibility |
| Port 8081 already in use | Change the port mapping in docker-compose.yml or stop the conflicting process |
| Container name conflict | Run docker stop scanner and docker rm scanner to clean up interrupted containers |
| Out of memory errors | Increase Docker Desktop memory allocation to 8GB or more |


## Disclaimer

This tool performs active security scanning against web applications. Only use against applications you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service. The author assumes no liability for unauthorized or improper use of this software.

## License

This project is licensed under the MIT License. See the LICENSE file for complete details.

MIT License summary: Permission is hereby granted, free of charge, to any person obtaining a copy of this software to use, copy, modify, merge, publish, distribute, sublicense, and sell copies of the software, subject to including the copyright notice and permission notice in all copies.

## Acknowledgments

- OWASP ZAP for providing the world's most popular free web security testing platform
- The open source security community for methodologies and best practices
- Inspired by professional penetration testing frameworks including NIST SP 800-115 and OWASP Testing Guide

## Author

Funso Isola

LinkedIn: linkedin.com/in/funisola/
