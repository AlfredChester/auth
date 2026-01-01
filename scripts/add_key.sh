#!/bin/bash

# Color codes for better UI
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Auth Service Key Manager ===${NC}"
echo "This script will add a new product key to the Cloudflare D1 database (Remote)."
echo ""

# 1. Get SemVer Range
echo -e "${YELLOW}Step 1: Enter SemVer Range${NC}"
echo "Examples: '>=1.0.0 <2.0.0', '^1.2.3', '1.x'"
echo "Please ensure it follows standard SemVer specifications."
read -p "Range: " SEMVER_RANGE

if [ -z "$SEMVER_RANGE" ]; then
    echo -e "${RED}Error: SemVer range cannot be empty.${NC}"
    exit 1
fi

echo ""

# 2. Get Product Key
echo -e "${YELLOW}Step 2: Enter Product Key${NC}"
echo "It is recommended to use a high-entropy string, such as a JWT or a random 64-character hex string."
echo "You can generate one using: openssl rand -hex 32"
read -p "Key: " PRODUCT_KEY

if [ -z "$PRODUCT_KEY" ]; then
    echo -e "${RED}Error: Product Key cannot be empty.${NC}"
    exit 1
fi

echo ""

# 3. Confirmation
echo -e "${BLUE}=== Confirmation ===${NC}"
echo -e "SemVer Range : ${GREEN}$SEMVER_RANGE${NC}"
echo -e "Product Key  : ${GREEN}$PRODUCT_KEY${NC}"
echo ""
read -p "Are you sure you want to add this key to the REMOTE database? (y/N) " CONFIRM

if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Operation cancelled."
    exit 0
fi

# 4. Execute
echo ""
echo "Adding key to database..."
# Note: We use single quotes for SQL values, so we need to be careful if the input contains single quotes.
# For simplicity, we assume standard keys/ranges without single quotes.
npx wrangler d1 execute auth-db --remote --command "INSERT INTO product_keys (key_value, semver_range) VALUES ('$PRODUCT_KEY', '$SEMVER_RANGE');"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Success! Key added.${NC}"
else
    echo -e "${RED}Failed to add key. Please check the error message above.${NC}"
fi
