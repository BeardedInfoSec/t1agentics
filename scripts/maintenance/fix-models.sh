#!/bin/bash

echo "========================================"
echo "T1 Agentics - Model Fetch Fix"
echo "========================================"
echo ""

echo "Fetching vLLM model information..."
MODEL_INFO=$(curl -s http://localhost:8001/v1/models | jq -r '.data[0] | {id: .id, name: .id}')
MODEL_ID=$(echo "$MODEL_INFO" | jq -r '.id')

if [ -z "$MODEL_ID" ] || [ "$MODEL_ID" = "null" ]; then
    echo "❌ Could not fetch model from vLLM"
    exit 1
fi

echo "✅ Found model: $MODEL_ID"
echo ""

echo "Getting AI provider ID..."
PROVIDER_ID=$(sudo docker exec t1agentics-postgres psql -U agentcore -d agentcore -t -c "SELECT id FROM ai_providers WHERE provider_type = 'openai_compatible' ORDER BY created_at DESC LIMIT 1;" | tr -d ' ')

if [ -z "$PROVIDER_ID" ]; then
    echo "❌ No vLLM provider found in database"
    exit 1
fi

echo "✅ Provider ID: $PROVIDER_ID"
echo ""

echo "Updating provider with model..."
MODEL_JSON="[{\"id\": \"$MODEL_ID\", \"name\": \"$MODEL_ID\"}]"

sudo docker exec t1agentics-postgres psql -U agentcore -d agentcore -c "
UPDATE ai_providers
SET models = '$MODEL_JSON'::jsonb
WHERE id = '$PROVIDER_ID';
" > /dev/null

RESULT=$(sudo docker exec t1agentics-postgres psql -U agentcore -d agentcore -t -c "SELECT jsonb_array_length(models) FROM ai_providers WHERE id = '$PROVIDER_ID';" | tr -d ' ')

if [ "$RESULT" = "1" ]; then
    echo "✅ Successfully added model to provider!"
    echo ""
    echo "Model details:"
    echo "  ID: $MODEL_ID"
    echo "  Provider: vLLM (OpenAI Compatible)"
    echo "  Context Length: 8192 tokens"
    echo ""
    echo "You should now be able to:"
    echo "  1. See the model in Settings → AI Providers"
    echo "  2. Select it for agent configurations"
    echo "  3. Use it for AI triage and analysis"
else
    echo "❌ Failed to update provider"
    exit 1
fi

echo ""
echo "========================================"
echo "✅ Model fetch fix complete!"
echo "========================================"
