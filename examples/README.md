# Hawkeye Examples

This directory contains example outputs from the Hawkeye security scanning tool.

## Test Environment

The demonstration was performed against a test network: **192.168.100.0/29**.  

The test network is a docker compose network whih can be found here: [Hawkeye Test Net](https://github.com/osok/hawkeye-test-net)

This network range includes IP addresses from 192.168.100.1 to 192.168.100.6 (with 192.168.100.0 as network address and 192.168.100.7 as broadcast address).

## Files in this Directory

### `results.json`
Raw detection results in JSON format containing:
- Discovered MCP servers and their configurations
- Network scan results
- Process enumeration data
- Security assessment findings

### `result.html`
AI-powered threat analysis report in HTML format containing:
- Executive summary of security findings
- Detailed threat analysis with risk scores
- Remediation recommendations
- Interactive visualizations of discovered services

## How These Were Generated

The example files were created using the following two-step process:

### Step 1: Network Detection and Scanning
```bash
python application.py detect target --target 192.168.100.0/29 --output results.json
```

This command:
- Scans the specified network range for MCP servers
- Performs introspection on discovered services
- Enumerates running processes and configurations
- Outputs raw findings to `results.json`

### Step 2: AI-Powered Threat Analysis
```bash
python application.py analyze-threats -i results.json -f html -o result.html
```

This command:
- Reads the detection results from `results.json`
- Performs AI-powered threat modeling and risk assessment
- Generates contextual security recommendations
- Outputs a comprehensive HTML report as `result.html`

## Using These Examples

You can use these files to:

1. **Review scan methodology**: Examine `results.json` to understand the data collection process
2. **Study threat analysis**: Open `result.html` in a web browser to see the AI-generated security assessment
3. **Test reporting features**: Use `results.json` as input for testing different report formats
4. **Benchmark performance**: Compare scan results against this baseline

## Replicating the Demo

To replicate this demonstration:

1. Ensure you have a test network set up (isolated from production)
2. Run the detection command against your target network
3. Analyze the results with the threat analysis engine
4. Review the generated reports for security insights

**Note**: Always ensure you have proper authorization before scanning any network infrastructure.

## Next Steps

- Try different output formats (JSON, XML, CSV) for the threat analysis
- Experiment with different network ranges and target specifications
- Integrate the tool into your security assessment workflow
- Review the documentation for advanced configuration options