#!/bin/bash
# ============================================================================
# BUILD SCRIPT - BurpSuite HTML to DOCX Converter Docker Image
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  BurpSuite Converter - Docker Build${NC}"
echo -e "${BLUE}============================================${NC}"

# Create required directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p input output network_reports

# Build standard image
echo -e "${YELLOW}Building standard image...${NC}"
docker build -t burp-converter:latest --target production .

# Optionally build hardened image
if [ "$1" = "--hardened" ] || [ "$1" = "-h" ]; then
    echo -e "${YELLOW}Building hardened image...${NC}"
    docker build -t burp-converter:hardened --target hardened .
fi

# Show image info
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "Images created:"
docker images | grep burp-converter
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo "  1. Place HTML reports in ./input/"
echo "  2. Run: docker-compose run --rm burp-converter -i report.html"
echo "  3. Find output in ./output/"
echo ""
echo -e "${BLUE}Or use docker directly:${NC}"
echo '  docker run --rm -v $(pwd)/input:/app/input:ro -v $(pwd)/output:/app/output burp-converter -i report.html'
