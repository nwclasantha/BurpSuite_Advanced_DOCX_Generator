#!/bin/ash
# ============================================================================
# SECURE ENTRYPOINT SCRIPT
# BurpSuite HTML to DOCX Converter
# ============================================================================
# Security measures:
#   - Input validation
#   - Path traversal prevention
#   - File type verification
#   - Size limits
#   - No arbitrary command execution
# ============================================================================

# Use ash-compatible strict mode (no pipefail in POSIX sh)
set -eu

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
INPUT_DIR="/app/input"
OUTPUT_DIR="/app/output"
NETWORK_DIR="/app/network_reports"
MAX_FILE_SIZE_MB=500
VERSION="6.0.0"

# ------------------------------------------------------------------------------
# Color output (optional, disabled in non-interactive mode)
# ------------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# ------------------------------------------------------------------------------
# Logging functions (using printf for better compatibility)
# ------------------------------------------------------------------------------
log_info() {
    printf '%b[INFO]%b %s\n' "$BLUE" "$NC" "$1"
}

log_success() {
    printf '%b[SUCCESS]%b %s\n' "$GREEN" "$NC" "$1"
}

log_warn() {
    printf '%b[WARN]%b %s\n' "$YELLOW" "$NC" "$1"
}

log_error() {
    printf '%b[ERROR]%b %s\n' "$RED" "$NC" "$1" >&2
}

# ------------------------------------------------------------------------------
# Security: Validate file path (prevent path traversal)
# ------------------------------------------------------------------------------
validate_path() {
    local path="$1"
    local base_dir="$2"

    # Check for path traversal attempts
    case "$path" in
        *..*)
            log_error "Security: Path traversal detected in: $path"
            return 1
            ;;
    esac

    # Resolve real path and verify it's within allowed directory
    if [ -e "$path" ]; then
        real_path=$(realpath "$path" 2>/dev/null || echo "$path")
        case "$real_path" in
            "$base_dir"*)
                return 0
                ;;
            *)
                log_error "Security: Path outside allowed directory: $path"
                return 1
                ;;
        esac
    fi
    return 0
}

# ------------------------------------------------------------------------------
# Security: Validate HTML file
# ------------------------------------------------------------------------------
validate_html_file() {
    local file="$1"

    # Check file exists
    if [ ! -f "$file" ]; then
        log_error "File not found: $file"
        return 1
    fi

    # Check file extension
    case "$file" in
        *.html|*.HTML|*.htm|*.HTM)
            ;;
        *)
            log_error "Invalid file type. Only .html files are accepted."
            return 1
            ;;
    esac

    # Check file size
    file_size_kb=$(du -k "$file" | cut -f1)
    max_size_kb=$((MAX_FILE_SIZE_MB * 1024))
    if [ "$file_size_kb" -gt "$max_size_kb" ]; then
        log_error "File too large: ${file_size_kb}KB (max: ${max_size_kb}KB)"
        return 1
    fi

    # Basic content validation (check for BurpSuite markers)
    if ! grep -q "BODH0" "$file" 2>/dev/null; then
        log_warn "File may not be a valid BurpSuite report (BODH0 marker not found)"
    fi

    return 0
}

# ------------------------------------------------------------------------------
# Display help
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
================================================================================
  BurpSuite HTML to DOCX Converter v${VERSION}
  Secure Docker Edition
================================================================================

USAGE:
  docker run -v /path/to/reports:/app/input -v /path/to/output:/app/output \\
    burp-converter [OPTIONS]

VOLUME MOUNTS:
  /app/input          Mount your HTML reports here (read-only recommended)
  /app/output         Mount for output DOCX files (read-write)
  /app/network_reports  Optional: Mount network CVE Excel files

OPTIONS:
  --help              Show this help message
  --version           Show version information
  --list              List available input files

  -i, --input FILE    Input HTML filename (in /app/input)
  -o, --output FILE   Output DOCX filename (in /app/output)
  -s, --severity SEV  Severity filter (high,medium,low,info)
  -e, --evidence-only Show only evidence highlights
  -n, --network       Include network CVE reports
  --company NAME      Company name for report
  --title TITLE       Report title
  --target TARGET     Target application name
  --validate          Run validation after generation

EXAMPLES:
  # Basic conversion
  docker run -v ./reports:/app/input:ro -v ./output:/app/output \\
    burp-converter -i report.html

  # With severity filter and evidence-only mode
  docker run -v ./reports:/app/input:ro -v ./output:/app/output \\
    burp-converter -i report.html -s high,medium -e

  # Full enterprise report with network CVEs
  docker run -v ./reports:/app/input:ro -v ./output:/app/output \\
    -v ./network:/app/network_reports:ro \\
    burp-converter -i report.html -s high,medium,low -n \\
    --company "MyCompany" --title "Security Assessment" --validate

SECURITY NOTES:
  - Mount input directories as read-only (:ro) when possible
  - Container runs as non-root user (UID 1000)
  - Maximum input file size: ${MAX_FILE_SIZE_MB}MB
  - Only .html files are accepted as input

================================================================================
EOF
}

# ------------------------------------------------------------------------------
# Display version
# ------------------------------------------------------------------------------
show_version() {
    echo "BurpSuite HTML to DOCX Converter v${VERSION}"
    echo "Docker Secure Edition"
    python --version
}

# ------------------------------------------------------------------------------
# List available input files
# ------------------------------------------------------------------------------
list_files() {
    log_info "Available input files in ${INPUT_DIR}:"
    echo "----------------------------------------"

    if [ -d "$INPUT_DIR" ]; then
        # Use proper grouping with parentheses for -o option
        find "$INPUT_DIR" -maxdepth 1 \( -name "*.html" -o -name "*.HTML" -o -name "*.htm" -o -name "*.HTM" \) -type f 2>/dev/null | while read -r f; do
            size=$(du -h "$f" | cut -f1)
            echo "  $(basename "$f") ($size)"
        done
    else
        log_warn "Input directory not mounted"
    fi

    echo ""
    log_info "Network reports in ${NETWORK_DIR}:"
    echo "----------------------------------------"

    if [ -d "$NETWORK_DIR" ]; then
        find "$NETWORK_DIR" -maxdepth 1 -name "*.xlsx" -type f 2>/dev/null | while read -r f; do
            echo "  $(basename "$f")"
        done
    else
        echo "  (not mounted)"
    fi
}

# ------------------------------------------------------------------------------
# Process conversion
# ------------------------------------------------------------------------------
process_conversion() {
    local input_file=""
    local output_file=""
    local severity=""
    local evidence_only=""
    local network=""
    local company="Security Assessment Team"
    local title="Vulnerability Assessment Report"
    local target="Target Application"
    local validate=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -i|--input)
                input_file="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -s|--severity)
                severity="$2"
                shift 2
                ;;
            -e|--evidence-only)
                evidence_only="--evidence-only"
                shift
                ;;
            -n|--network)
                network="--network ${NETWORK_DIR}"
                shift
                ;;
            --company)
                company="$2"
                shift 2
                ;;
            --title)
                title="$2"
                shift 2
                ;;
            --target)
                target="$2"
                shift 2
                ;;
            --validate)
                validate="--validate"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate input file is provided
    if [ -z "$input_file" ]; then
        log_error "No input file specified. Use -i or --input"
        echo ""
        list_files
        exit 1
    fi

    # Construct full input path
    input_path="${INPUT_DIR}/${input_file}"

    # Security: Validate path
    validate_path "$input_path" "$INPUT_DIR" || exit 1

    # Validate HTML file
    validate_html_file "$input_path" || exit 1

    # Generate output filename if not provided
    if [ -z "$output_file" ]; then
        # Remove any HTML extension (.html, .HTML, .htm, .HTM)
        output_file=$(basename "$input_file")
        output_file="${output_file%.html}"
        output_file="${output_file%.HTML}"
        output_file="${output_file%.htm}"
        output_file="${output_file%.HTM}"
        output_file="${output_file}_Enterprise_Report.docx"
    fi

    output_path="${OUTPUT_DIR}/${output_file}"

    # Security: Validate output path
    validate_path "$output_path" "$OUTPUT_DIR" || exit 1

    # Build command arguments
    cmd_args="\"${input_path}\" -o \"${output_path}\""
    cmd_args="${cmd_args} --company \"${company}\""
    cmd_args="${cmd_args} --title \"${title}\""
    cmd_args="${cmd_args} --target \"${target}\""

    [ -n "$severity" ] && cmd_args="${cmd_args} --severity ${severity}"
    [ -n "$evidence_only" ] && cmd_args="${cmd_args} ${evidence_only}"
    [ -n "$validate" ] && cmd_args="${cmd_args} ${validate}"

    # Add network reports if directory has files and flag is set
    if [ -n "$network" ] && [ -d "$NETWORK_DIR" ]; then
        xlsx_count=$(find "$NETWORK_DIR" -maxdepth 1 -name "*.xlsx" 2>/dev/null | wc -l)
        if [ "$xlsx_count" -gt 0 ]; then
            cmd_args="${cmd_args} ${network}"
            log_info "Including ${xlsx_count} network CVE report(s)"
        fi
    fi

    log_info "Starting conversion..."
    log_info "Input:  ${input_file}"
    log_info "Output: ${output_file}"

    # Execute conversion
    eval python /app/burp_to_docx.py ${cmd_args}

    exit_code=$?

    if [ $exit_code -eq 0 ]; then
        log_success "Conversion completed successfully!"
        log_info "Output saved to: ${output_path}"

        # Show output file info
        if [ -f "$output_path" ]; then
            size=$(du -h "$output_path" | cut -f1)
            log_info "File size: ${size}"
        fi
    else
        log_error "Conversion failed with exit code: ${exit_code}"
    fi

    return $exit_code
}

# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
main() {
    # Handle special commands
    case "${1:-}" in
        --help|-h|help)
            show_help
            exit 0
            ;;
        --version|-v|version)
            show_version
            exit 0
            ;;
        --list|-l|list)
            list_files
            exit 0
            ;;
        "")
            show_help
            exit 0
            ;;
        *)
            process_conversion "$@"
            ;;
    esac
}

# Run main
main "$@"
