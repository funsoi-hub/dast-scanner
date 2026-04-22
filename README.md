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
- Extended Timeout Handling - No inactivity timeout, scan runs to completion

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

Clone the repository and navigate to the project folder:

git clone https://github.com/YOUR_USERNAME/dast-scanner-public.git
cd dast-scanner-public

### Usage

Run a scan using the Windows batch file:

docker-scan.bat

Enter the target URL when prompted. The scan will run for approximately 45-90 minutes depending on application size.

Alternatively, use Docker Compose directly:

docker compose up -d zap
docker compose build scanner
docker compose run --rm scanner --url https://example.com --active-timeout 7200

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| --url | Target URL to scan | Required |
| --active-timeout | Max scan duration in seconds | 7200 (2 hours) |
| --scan-id | Custom scan identifier | Auto-generated |
| --zap-host | ZAP API host | localhost |
| --zap-port | ZAP API port | 8080 |

## Windows Batch Files

| File | Purpose |
|------|---------|
| docker-scan.bat | Main launcher - starts ZAP and runs scan |
| docker-rebuild.bat | Rebuild scanner image after code changes |
| docker-stop.bat | Stop all containers |
| docker-status.bat | Check container and report status |
| cleanup.bat | Delete all reports and reset containers |

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
- Vulnerability Summary Table
- Detailed findings with evidence and remediation steps

## Scan Phases and Timing

| Phase | Progress | Activity | Typical Duration |
|-------|----------|----------|------------------|
| Spider Discovery | 0-36% | URL enumeration and passive analysis | 5-10 minutes |
| Active Attacks | 36-37% | SQLi, XSS, CSRF probes | 20-40 minutes |
| Completion | 37-100% | Remaining checks and alert processing | 10-20 minutes |


## Project Structure

```
dast-scanner-public/
├── dast_scanner.py          # Main scanner application
├── docker-compose.yml       # Docker services configuration
├── Dockerfile               # Scanner container build
├── requirements.txt         # Python dependencies
├── docker-scan.bat          # Windows launcher script
├── docker-rebuild.bat       # Rebuild scanner image
├── docker-stop.bat          # Stop containers
├── docker-status.bat        # Check status
├── cleanup.bat              # Reset all data
├── .gitignore               # Git ignore rules
├── LICENSE                  # MIT License
└── README.md                # This file
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| ZAP container fails to start | Increase Docker memory to at least 4GB in Docker Desktop settings |
| Scan stalls at 36-37% with "continuing" messages | This is normal. Wait 20-40 minutes for active attack phase to complete |
| No URLs discovered | Target may be a single page application or has no crawlable links. Verify target accessibility |
| Port 8081 already in use | Change the port mapping in docker-compose.yml or stop the conflicting process |
| Container name conflict | Run cleanup.bat to reset all containers and networks |
| Out of memory errors | Increase Docker Desktop memory allocation to 8GB or more |
| "ZAP is taking longer than expected" | First run downloads addons. Wait up to 2 minutes |

## Maintenance Commands

Check status of containers and reports:

docker-status.bat

Rebuild scanner after updating code:

docker-rebuild.bat

Stop all containers when not in use:

docker-stop.bat

Reset everything and delete all reports:

cleanup.bat

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch using git checkout -b feature/amazing-feature
3. Commit your changes using git commit -m 'Add amazing feature'
4. Push to the branch using git push origin feature/amazing-feature
5. Open a Pull Request on GitHub

## Disclaimer

This tool performs active security scanning against web applications. Only use against applications you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service. The author assumes no liability for unauthorized or improper use of this software.

## License

This project is licensed under the MIT License. See the LICENSE file for complete details.

MIT License summary: Permission is hereby granted, free of charge, to any person obtaining a copy of this software to use, copy, modify, merge, publish, distribute, sublicense, and sell copies of the software, subject to including the copyright notice and permission notice in all copies.

## Acknowledgments

- OWASP ZAP for providing the world's most popular free web security testing platform
- The open source security community for methodologies and best practices
- Inspired by professional penetration testing frameworks including NIST SP 800-115 and OWASP Testing Guide
