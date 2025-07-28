#!/bin/bash

# HawkEye AI Threat Analysis Workflow Example
# This script demonstrates the complete workflow from MCP detection to AI-powered threat analysis

echo "🦅 HawkEye AI Threat Analysis Workflow Demo"
echo "=============================================="

# Activate virtual environment
source venv/bin/activate

# Step 1: Create sample detection results (simulating a real detection)
echo "📂 Step 1: Creating sample detection results..."
cat > sample_detection.json << 'EOF'
{
  "metadata": {
    "scan_target": "localhost",
    "scan_date": "2024-12-28T12:00:00Z",
    "detection_method": "comprehensive"
  },
  "detection_results": [
    {
      "target_host": "localhost",
      "confidence": 0.95,
      "detection_method": "process_enum",
      "mcp_server": {
        "server_id": "filesystem-mcp-demo",
        "server_url": "stdio://npx/@modelcontextprotocol/server-filesystem",
        "transport_type": "stdio",
        "port": null,
        "tools": [
          {
            "name": "read_file",
            "description": "Read contents of a file from the filesystem",
            "input_schema": {
              "type": "object",
              "properties": {
                "path": {"type": "string", "description": "File path to read"}
              },
              "required": ["path"]
            }
          },
          {
            "name": "write_file", 
            "description": "Write content to a file on the filesystem",
            "input_schema": {
              "type": "object",
              "properties": {
                "path": {"type": "string", "description": "File path to write"},
                "content": {"type": "string", "description": "Content to write"}
              },
              "required": ["path", "content"]
            }
          },
          {
            "name": "list_directory",
            "description": "List contents of a directory",
            "input_schema": {
              "type": "object",
              "properties": {
                "path": {"type": "string", "description": "Directory path to list"}
              },
              "required": ["path"]
            }
          }
        ],
        "capabilities": [
          {
            "name": "filesystem",
            "description": "File system access capabilities",
            "capabilities": ["read", "write", "list"],
            "metadata": {"version": "1.0"}
          }
        ],
        "metadata": {
          "name": "Filesystem MCP Server",
          "version": "1.0.0",
          "command_line": "npx @modelcontextprotocol/server-filesystem /tmp",
          "process_id": 12345
        }
      }
    },
    {
      "target_host": "localhost",
      "confidence": 0.88,
      "detection_method": "process_enum", 
      "mcp_server": {
        "server_id": "web-search-mcp-demo",
        "server_url": "stdio://npx/@modelcontextprotocol/server-web-search",
        "transport_type": "stdio",
        "port": null,
        "tools": [
          {
            "name": "web_search",
            "description": "Search the web for information",
            "input_schema": {
              "type": "object",
              "properties": {
                "query": {"type": "string", "description": "Search query"},
                "max_results": {"type": "integer", "description": "Maximum number of results"}
              },
              "required": ["query"]
            }
          }
        ],
        "capabilities": [
          {
            "name": "web_search",
            "description": "Web search capabilities",
            "capabilities": ["search", "retrieve"],
            "metadata": {"version": "1.0"}
          }
        ],
        "metadata": {
          "name": "Web Search MCP Server",
          "version": "1.0.0",
          "command_line": "npx @modelcontextprotocol/server-web-search",
          "process_id": 23456
        }
      }
    }
  ],
  "summary": {
    "total_servers_detected": 2,
    "high_confidence_detections": 1,
    "medium_confidence_detections": 1
  }
}
EOF

echo "✅ Sample detection results created in sample_detection.json"

# Step 2: Run AI threat analysis on the detection results
echo ""
echo "🤖 Step 2: Running AI threat analysis..."
echo "Note: This will use rule-based fallback if no AI API keys are configured"

python -m src.hawkeye detect analyze-threats \
  --input sample_detection.json \
  --output threat_analysis.json \
  --format json \
  --analysis-type comprehensive \
  --confidence-threshold 0.5 \
  --parallel-processing \
  --max-workers 2

# Check if analysis was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Threat analysis completed successfully!"
    
    # Step 3: Show results summary
    echo ""
    echo "📊 Step 3: Analysis Results Summary"
    echo "===================================="
    
    if [ -f threat_analysis.json ]; then
        echo "✅ Threat analysis results saved to: threat_analysis.json"
        
        # Extract key information from the results (if jq is available)
        if command -v jq &> /dev/null; then
            echo ""
            echo "📈 Key Findings:"
            echo "  • Total servers analyzed: $(jq '.metadata.total_servers_analyzed // 0' threat_analysis.json)"
            echo "  • Successful analyses: $(jq '.metadata.successful_analyses // 0' threat_analysis.json)"
            echo "  • Analysis type: $(jq -r '.metadata.analysis_type // "unknown"' threat_analysis.json)"
            echo "  • AI enabled: $(jq '.metadata.ai_enabled // false' threat_analysis.json)"
            
            # Show threat levels if available
            if [ "$(jq '.threat_analyses | length' threat_analysis.json)" -gt 0 ]; then
                echo ""
                echo "🎯 Threat Analysis Results:"
                jq -r '.threat_analyses | to_entries[] | "  • \(.key): Threat Level = \(.value.threat_level // "unknown")"' threat_analysis.json
            fi
        else
            echo "  (Install 'jq' for detailed JSON analysis)"
        fi
    else
        echo "⚠️ Threat analysis file not found - check for errors above"
    fi
    
    # Step 4: Generate HTML report
    echo ""
    echo "📄 Step 4: Generating HTML report..."
    
    python -m src.hawkeye detect analyze-threats \
      --input sample_detection.json \
      --output threat_report.html \
      --format html \
      --analysis-type comprehensive
    
    if [ $? -eq 0 ] && [ -f threat_report.html ]; then
        echo "✅ HTML threat report generated: threat_report.html"
    else
        echo "⚠️ HTML report generation failed"
    fi
    
else
    echo "❌ Threat analysis failed - check the error messages above"
    echo ""
    echo "💡 Tips:"
    echo "  • Ensure the virtual environment is activated"
    echo "  • For AI analysis, configure API keys in .env file:"
    echo "    AI_PROVIDER=anthropic"
    echo "    AI_ANTHROPIC_API_KEY=your_key_here"
    echo "  • The system will fall back to rule-based analysis without API keys"
fi

echo ""
echo "🎉 Workflow demonstration complete!"
echo ""
echo "Files created:"
echo "  • sample_detection.json - Sample MCP detection results"
echo "  • threat_analysis.json - AI threat analysis results (if successful)"  
echo "  • threat_report.html - HTML threat report (if successful)"
echo ""
echo "Next steps:"
echo "  1. Configure AI API keys for full AI-powered analysis"
echo "  2. Run real detections: hawkeye detect local -o real_detection.json"
echo "  3. Analyze real results: hawkeye detect analyze-threats -i real_detection.json"
echo ""
echo "This replaces the previous demo-only approach with a production-ready workflow!" 