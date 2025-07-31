# Filesystem MCP Server - Access Guide

## Overview

The Filesystem MCP server provides **12 file operation tools** accessible via HTTP API. It runs at:
- **Container IP**: `192.168.100.3:3001`
- **Host Access**: `localhost:3001` (via port mapping)
- **Transport**: HTTP with MCP JSON-RPC protocol
- **Session Management**: Required (session ID in HTTP headers)

## Quick Access Steps

### Step 1: Initialize MCP Session

```bash
curl -v -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{"roots":{"listChanged":false}},
      "clientInfo":{"name":"test-client","version":"1.0.0"}
    }
  }'
```

**Look for this in the response headers:**
```
< mcp-session-id: b14df229-be39-4e22-8225-ed0303faa04d
```

### Step 2: List Available Tools

```bash
curl -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: b14df229-be39-4e22-8225-ed0303faa04d" \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/list",
    "params":{}
  }' | jq '.result.tools'
```

### Step 3: Call a Specific Tool (Example)

```bash
curl -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: b14df229-be39-4e22-8225-ed0303faa04d" \
  -d '{
    "jsonrpc":"2.0",
    "id":3,
    "method":"tools/call",
    "params":{
      "name":"list_allowed_directories",
      "arguments":{}
    }
  }' | jq '.result'
```

## Complete Tool List

The filesystem MCP server provides these 12 tools:

### File Reading Tools
- **`read_file`** - Read complete file contents (with head/tail options)
- **`read_multiple_files`** - Read multiple files simultaneously
- **`get_file_info`** - Get file metadata (size, timestamps, permissions)

### File Writing Tools
- **`write_file`** - Create new file or overwrite existing file
- **`edit_file`** - Line-based file editing with git-style diff output

### Directory Tools
- **`create_directory`** - Create directories (supports nested creation)
- **`list_directory`** - List directory contents with [FILE]/[DIR] prefixes
- **`list_directory_with_sizes`** - List directory contents with file sizes
- **`directory_tree`** - Recursive JSON tree structure of directories

### File Management Tools
- **`move_file`** - Move/rename files and directories
- **`search_files`** - Recursive file search with pattern matching

### Security Tools
- **`list_allowed_directories`** - Show which directories are accessible

## Example Tool Calls

### List Allowed Directories
```bash
curl -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: [SESSION-ID]" \
  -d '{
    "jsonrpc":"2.0",
    "id":3,
    "method":"tools/call",
    "params":{
      "name":"list_allowed_directories",
      "arguments":{}
    }
  }'
```

### Read a File
```bash
curl -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: [SESSION-ID]" \
  -d '{
    "jsonrpc":"2.0",
    "id":4,
    "method":"tools/call",
    "params":{
      "name":"read_file",
      "arguments":{
        "path":"/tmp/example.txt"
      }
    }
  }'
```

### List Directory Contents
```bash
curl -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: [SESSION-ID]" \
  -d '{
    "jsonrpc":"2.0",
    "id":5,
    "method":"tools/call",
    "params":{
      "name":"list_directory",
      "arguments":{
        "path":"/tmp"
      }
    }
  }'
```

### Create a File
```bash
curl -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: [SESSION-ID]" \
  -d '{
    "jsonrpc":"2.0",
    "id":6,
    "method":"tools/call",
    "params":{
      "name":"write_file",
      "arguments":{
        "path":"/tmp/test.txt",
        "content":"Hello, MCP World!"
      }
    }
  }'
```

## Automated Session Script

Here's a complete script that handles session management automatically:

```bash
#!/bin/bash

# Step 1: Initialize and extract session ID
INIT_RESPONSE=$(curl -s -v -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{"roots":{"listChanged":false}},
      "clientInfo":{"name":"test-client","version":"1.0.0"}
    }
  }' 2>&1)

# Extract session ID from headers
SESSION_ID=$(echo "$INIT_RESPONSE" | grep -i "mcp-session-id:" | cut -d' ' -f3 | tr -d '\r')

echo "Session ID: $SESSION_ID"

# Step 2: List tools
echo "=== Available Tools ==="
curl -s -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/list",
    "params":{}
  }' | jq -r '.result.tools[].name'

# Step 3: Test a tool
echo "=== Testing list_allowed_directories ==="
curl -s -X POST http://192.168.100.3:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc":"2.0",
    "id":3,
    "method":"tools/call",
    "params":{
      "name":"list_allowed_directories",
      "arguments":{}
    }
  }' | jq '.result'
```

Save this as `test-filesystem-mcp.sh`, make it executable with `chmod +x test-filesystem-mcp.sh`, and run it.

## Technical Details

### Protocol Information
- **JSON-RPC Version**: 2.0
- **Protocol Version**: 2024-11-05
- **Transport**: HTTP POST requests
- **Content-Type**: application/json
- **Session Management**: Via `Mcp-Session-Id` header

### Server Information
- **Server Name**: secure-filesystem-server
- **Version**: 0.2.0
- **Implementation**: @modelcontextprotocol/server-filesystem
- **Proxy**: mcp-streamablehttp-proxy (Python)
- **Base Directory**: /tmp (configurable)

### Security Features
- **Directory Restrictions**: Only operates within allowed directories
- **Session-based Access**: Each client session is isolated
- **Input Validation**: All tool parameters validated via JSON Schema

## Container Access Options

### Direct Container IP (Recommended for Testing)
```bash
http://192.168.100.3:3001/mcp
```

### Via Host Port Mapping
```bash
http://localhost:3001/mcp
```

### Via Gateway (Proxied)
```bash
http://localhost:8000/filesystem/
```

## Error Handling

Common errors and solutions:

### Session ID Required
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32002,
    "message": "Session ID required. Please include Mcp-Session-Id header from initialize response."
  }
}
```
**Solution**: Always initialize session first and include the session ID header.

### Invalid Tool Name
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32601,
    "message": "Method not found"
  }
}
```
**Solution**: Use `tools/list` to see available tool names, then use `tools/call` to invoke them.

### Path Access Denied
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "error": {
    "code": -32603,
    "message": "Access denied: Path outside allowed directories"
  }
}
```
**Solution**: Use `list_allowed_directories` tool to see which paths are accessible.

---

**Last Updated**: Based on actual testing of filesystem-mcp container
**Status**: ✅ Fully functional with 12 confirmed tools
**Container**: 192.168.100.3:3001 