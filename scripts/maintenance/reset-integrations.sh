#!/bin/bash

echo "========================================"
echo "T1 Agentics - Integration Reset Tool"
echo "========================================"
echo ""

echo "This script will help you:"
echo "1. See what integrations are currently loaded"
echo "2. Import fresh integrations from the catalog"
echo ""

# Get authentication token
echo "Logging in..."
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "❌ Login failed! Make sure backend is running."
    exit 1
fi

echo "✅ Logged in successfully"
echo ""

# Function to search catalog
search_catalog() {
    local query=$1
    echo "Searching catalog for: $query"
    curl -s "http://localhost:8000/api/v1/catalog/connectors/search?query=$query&limit=5" \
      | jq -r '.results[] | "\(.id) - \(.name) (\(.action_count) actions)"'
}

# Function to import connector
import_connector() {
    local connector_id=$1
    echo "Importing connector: $connector_id"

    RESULT=$(curl -s -X POST "http://localhost:8000/api/v1/catalog/connectors/import" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $TOKEN" \
      -d "{\"connector_id\":\"$connector_id\",\"enabled\":false}")

    if echo "$RESULT" | jq -e '.detail' > /dev/null 2>&1; then
        ERROR=$(echo "$RESULT" | jq -r '.detail')
        if [[ "$ERROR" == *"already exists"* ]]; then
            echo "  ⚠️  Already imported: $connector_id"
        else
            echo "  ❌ Error: $ERROR"
        fi
    else
        echo "  ✅ Successfully imported!"
        echo "$RESULT" | jq -r '.message' 2>/dev/null || echo ""
    fi
}

# Show menu
while true; do
    echo ""
    echo "What would you like to do?"
    echo "1) Search for a connector in catalog"
    echo "2) Import URLScan.io (recommended version)"
    echo "3) Import multiple threat intel integrations"
    echo "4) List currently loaded integrations"
    echo "5) Exit"
    echo ""
    read -p "Choose an option (1-5): " choice

    case $choice in
        1)
            read -p "Enter search term: " query
            search_catalog "$query"
            ;;
        2)
            echo ""
            echo "Importing recommended URLScan.io connector..."
            import_connector "urlscan_io"
            ;;
        3)
            echo ""
            echo "Importing common threat intel integrations..."
            echo ""
            for connector in virustotal abuseipdb urlscan_io otx alienvault shodan greynoise; do
                echo "→ $connector"
                import_connector "$connector"
                sleep 1
            done
            ;;
        4)
            echo ""
            echo "Fetching current integrations..."
            curl -s "http://localhost:8000/api/v1/integrations/" \
              -H "Authorization: Bearer $TOKEN" \
              | jq -r '.integrations[] | "\(.id) - \(.name) (Enabled: \(.enabled))"' | head -20
            ;;
        5)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please choose 1-5."
            ;;
    esac
done
