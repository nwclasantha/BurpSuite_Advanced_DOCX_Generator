# BurpSuite HTML to DOCX Report Converter

<img width="1536" height="1024" alt="Burp" src="https://github.com/user-attachments/assets/3bc2f6c0-d80a-4002-9ff5-d4a7aae33b7e" />

**Enterprise-grade security report generator** that converts BurpSuite HTML vulnerability scan reports into professional, executive-ready DOCX documents.

## Objective

Transform raw BurpSuite HTML scan outputs into polished, enterprise-quality security assessment reports suitable for:
- Executive presentations
- Compliance audits
- Client deliverables
- Security team documentation

## Key Features

| Feature | Description |
|---------|-------------|
| Executive Summary | Risk score dashboard with visual indicators |
| Severity Filtering | Filter by High, Medium, Low, Info |
| Evidence-Only Mode | Compact reports showing only highlighted evidence |
| Network CVE Assessment | Integrate network vulnerability Excel reports |
| OWASP Mapping | Automatic OWASP Top 10 compliance mapping |
| Risk Matrix | Severity x Confidence assessment matrix |
| Professional Styling | Enterprise typography and branding |

## Security Features

- Non-root execution (UID 1000)
- Read-only filesystem support
- Input validation & path traversal prevention
- File type and size limits
- No privilege escalation

## Quick Start

```bash
# Pull the image
docker pull nwclasantha/burp-converter:latest

# Create directories
mkdir -p input output network_reports

# Place your BurpSuite HTML report in ./input/
# Place network CVE Excel files in ./network_reports/ (optional)
```

## Usage Examples

### Full Report (All Severities + Network CVEs)

```bash
docker run --rm \
  -v "$(pwd)/input:/app/input:ro" \
  -v "$(pwd)/output:/app/output" \
  -v "$(pwd)/network_reports:/app/network_reports:ro" \
  nwclasantha/burp-converter:latest \
  -i BurpSuite-VAPT-Full-Scan-Report.html \
  -s high,medium,low,info \
  -n \
  --company "ABC" \
  --title "Security Assessment" \
  --target "Application" \
  --validate
```

### Evidence-Only Report (Compact + Network CVEs)

```bash
docker run --rm \
  -v "$(pwd)/input:/app/input:ro" \
  -v "$(pwd)/output:/app/output" \
  -v "$(pwd)/network_reports:/app/network_reports:ro" \
  nwclasantha/burp-converter:latest \
  -i BurpSuite-VAPT-Full-Scan-Report.html \
  -s high,medium,low,info \
  -e -n \
  --company "ABC" \
  --title "Security Assessment" \
  --target "Application" \
  --validate
```

### Executive Report (High/Medium Only)

```bash
docker run --rm \
  -v "$(pwd)/input:/app/input:ro" \
  -v "$(pwd)/output:/app/output" \
  nwclasantha/burp-converter:latest \
  -i BurpSuite-Report.html \
  -s high,medium \
  -e \
  --company "ABC" \
  --title "Executive Security Summary" \
  --target "Application"
```

### Windows (Git Bash/MSYS2)

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$(pwd)/input:/app/input:ro" \
  -v "$(pwd)/output:/app/output" \
  -v "$(pwd)/network_reports:/app/network_reports:ro" \
  nwclasantha/burp-converter:latest \
  -i BurpSuite-Report.html \
  -s high,medium,low,info \
  -n \
  --company "ABC" \
  --title "Security Assessment" \
  --target "Application" \
  --validate
```

## Command Options

| Option | Short | Description |
|--------|-------|-------------|
| `--input` | `-i` | Input HTML filename (required) |
| `--output` | `-o` | Output DOCX filename |
| `--severity` | `-s` | Severity filter: high,medium,low,info |
| `--evidence-only` | `-e` | Show only evidence highlights |
| `--network` | `-n` | Include network CVE reports |
| `--company` | | Company name for report header |
| `--title` | | Report title |
| `--target` | | Target application name |
| `--validate` | | Run validation checks |
| `--help` | | Show help message |
| `--list` | | List available input files |

## Volume Mounts

| Container Path | Purpose | Mode |
|---------------|---------|------|
| `/app/input` | HTML input files | Read-only (`:ro`) |
| `/app/output` | DOCX output files | Read-write |
| `/app/network_reports` | Network CVE Excel files | Read-only (`:ro`) |

## Report Sections Generated

1. **Cover Page** - Professional title page with company branding
2. **Executive Summary** - Risk score, scope, key findings
3. **Severity Charts** - Visual distribution of findings
4. **OWASP Compliance** - Top 10 mapping
5. **Remediation Priority** - Prioritized fix recommendations
6. **Risk Matrix** - Severity vs Confidence analysis
7. **Vulnerability Summary** - Overview table
8. **Detailed Findings** - Full vulnerability details with evidence
9. **Network Assessment** - CVE findings from network scans (optional)
10. **Appendix** - Methodology and definitions

## Tags

- `latest` - Most recent stable version
- `6.0.0` - Version 6.0.0 release

## Support

For issues and feature requests, visit the repository.

## License

MIT License
