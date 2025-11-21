# Setting Up NVD MCP Server with Claude Code

## Quick Start Guide

### Step 0: Get an NVD API Key (Recommended)

While the server works without an API key, it's **highly recommended** to get one for better rate limits:

- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds (10x faster!)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Request a free API key (delivered via email instantly)
3. Set the environment variable:
   - **Windows**: `setx NVD_API_KEY "YOUR_API_KEY_HERE"`
   - **macOS/Linux**: Add to `~/.bashrc` or `~/.zshrc`: `export NVD_API_KEY="YOUR_API_KEY_HERE"`

### Option 1: Claude Code Desktop App

1. **Locate your Claude Desktop configuration file:**
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

2. **Edit the configuration file** and add the NVD server:

**With API Key (Recommended):**
```json
{
  "mcpServers": {
    "nvd": {
      "command": "node",
      "args": ["/path/to/nvd-mcp-server/index.js"],
      "env": {
        "NVD_API_KEY": "YOUR_NVD_API_KEY_HERE"
      }
    }
  }
}
```

**Without API Key:**
```json
{
  "mcpServers": {
    "nvd": {
      "command": "node",
      "args": ["/path/to/nvd-mcp-server/index.js"]
    }
  }
}
```

**Important**: Replace `/path/to/nvd-mcp-server/index.js` with the actual path to your installation.

3. **Restart Claude Desktop** to load the new MCP server.

4. **Verify it's working** by asking Claude:
   ```
   "Can you search for recent critical CVEs?"
   ```

### Option 2: Claude Code CLI in VSCode

If you're using Claude Code as a CLI tool in your terminal/VSCode:

1. **Navigate to your project directory:**
   ```bash
   cd G:\ai_ghost_chat
   ```

2. **Add the MCP server using Claude CLI:**
   ```bash
   claude mcp add nvd node "G:\ai_ghost_chat\nvd-mcp-server\index.js"
   ```

3. **Verify the server is added:**
   ```bash
   claude mcp list
   ```

4. **Reconnect the MCP servers:**
   ```bash
   claude mcp reconnect
   ```

### Option 3: Project-Specific Configuration

For project-specific MCP configuration, create a `.clauderc` file in your project root:

```json
{
  "mcpServers": {
    "nvd": {
      "command": "node",
      "args": ["./nvd-mcp-server/index.js"]
    }
  }
}
```

## New Features in This Implementation

### 🚀 Enhancements Over Python Version

This Node.js/npx implementation includes several improvements:

1. **API Key Support**: Automatic rate limit increase (5 → 50 requests/30s)
2. **Concise Mode**: Get one-line summaries instead of full details
3. **More Tools**: 4 tools vs 2 in the Python version
4. **No Docker Required**: Simpler setup with just Node.js
5. **Change History**: Track CVE modifications over time
6. **Recent CVEs Helper**: Quick search for latest vulnerabilities

### 📋 Concise Output Mode

For faster scanning and better readability, use `concise: true`:

**Example:**
```
"Show me the last 50 critical CVEs in concise format"
```

**Concise Output:**
```
CVE-2024-12345 | CVSS: 9.8 (CRITICAL) | Remote code execution in Apache component... [⚠️  KEV]
CVE-2024-12344 | CVSS: 9.1 (CRITICAL) | Authentication bypass in Microsoft product...
CVE-2024-12343 | CVSS: 9.0 (CRITICAL) | SQL injection vulnerability in PHP library...
```

**Full Output** (default):
```
================================================================================
[1] CVE-2024-12345
================================================================================
Published: 2024-11-20T10:15:00.000
Last Modified: 2024-11-21T08:30:00.000
Status: Analyzed

Description:
A remote code execution vulnerability exists in Apache...

CVSS Scores:
  CVSSv3.1: 9.8 (CRITICAL)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
...
```

## Using All Available Commands

Once the NVD MCP server is configured, you can use it with Claude Code through natural language. Here are all the available tools:

### 1. Search CVEs (`search_cves`)

**Examples:**
- "Search for CVEs related to Microsoft Exchange"
- "Find high severity vulnerabilities in the last 30 days"
- "Show me CVEs with CWE-89 (SQL Injection)"
- "List CVEs affecting Linux kernel versions 5.x"

**All Available Parameters:**
```javascript
{
  cveId: "CVE-2021-44228",              // Specific CVE ID
  cpeName: "cpe:2.3:a:...",             // CPE name filter
  keywordSearch: "apache log4j",        // Keyword search
  keywordExactMatch: true,              // Exact phrase match
  cvssV3Severity: "CRITICAL",           // LOW|MEDIUM|HIGH|CRITICAL
  cvssV3Metrics: "AV:N/AC:L/...",       // CVSS v3 vector
  cvssV2Severity: "HIGH",               // LOW|MEDIUM|HIGH
  cvssV2Metrics: "AV:N/AC:L/...",       // CVSS v2 vector
  cweId: "CWE-287",                     // CWE identifier
  hasKev: true,                         // CISA KEV only
  hasCertAlerts: true,                  // US-CERT alerts only
  hasCertNotes: true,                   // CERT/CC notes only
  hasOval: true,                        // OVAL info only
  pubStartDate: "2023-01-01T00:00:00.000Z",
  pubEndDate: "2023-12-31T23:59:59.999Z",
  lastModStartDate: "2023-01-01T00:00:00.000Z",
  lastModEndDate: "2023-12-31T23:59:59.999Z",
  sourceIdentifier: "cve@mitre.org",
  noRejected: true,                     // Exclude rejected CVEs
  resultsPerPage: 20,                   // Max 2000
  startIndex: 0,                        // Pagination offset
  concise: false                        // NEW: One-line summaries (default: false)
}
```

### 2. Get CVE by ID (`get_cve_by_id`)

**Examples:**
- "Get details for CVE-2021-44228"
- "Show me information about CVE-2023-12345"
- "What is CVE-2024-0001?"
- "Get a concise summary of CVE-2021-44228"

**Parameters:**
```javascript
{
  cveId: "CVE-2021-44228",  // Required
  concise: false             // NEW: One-line summary (default: false)
}
```

### 3. Get CVE Change History (`get_cve_change_history`)

**Examples:**
- "Show me the change history for CVE-2021-44228"
- "What changes were made to CVEs in January 2024?"
- "List all rejected CVEs in the last week"

**Parameters:**
```javascript
{
  cveId: "CVE-2021-44228",              // Optional: specific CVE
  changeStartDate: "2023-01-01T00:00:00.000Z",
  changeEndDate: "2023-12-31T23:59:59.999Z",
  eventName: "Initial Analysis",        // See event types below
  resultsPerPage: 100,                  // Max 5000
  startIndex: 0
}
```

**Event Name Options:**
- `CVE Received`
- `Initial Analysis`
- `Reanalysis`
- `CVE Modified`
- `Modified Analysis`
- `CVE Translated`
- `Vendor Comment`
- `CVE Source Update`
- `CPE Deprecation Remap`
- `CWE Remap`
- `Reference Tag Update`
- `CVE Rejected`
- `CVE Unrejected`
- `CVE CISA KEV Update`

### 4. Search Recent CVEs (`search_recent_cves`)

**Examples:**
- "Show me CVEs from the last 7 days"
- "What critical vulnerabilities were published this week?"
- "Find high severity CVEs modified in the last 30 days"

**Parameters:**
```javascript
{
  days: 7,                              // Default: 7, Max: 120
  type: "published",                    // "published" or "modified"
  severity: "CRITICAL",                 // Optional: LOW|MEDIUM|HIGH|CRITICAL
  hasKev: true,                         // Optional: KEV only
  resultsPerPage: 20                    // Default: 20
}
```

## Complete Usage Examples

### Example 1: Security Monitoring
```
"Show me all critical CVEs added to CISA's KEV catalog in the last 30 days"
```
Claude will use:
```javascript
search_recent_cves({
  days: 30,
  type: "modified",
  severity: "CRITICAL",
  hasKev: true
})
```

### Example 2: Vulnerability Research
```
"Find all CVEs related to SQL injection (CWE-89) affecting Microsoft products"
```
Claude will use:
```javascript
search_cves({
  cweId: "CWE-89",
  keywordSearch: "Microsoft",
  resultsPerPage: 50
})
```

### Example 3: Specific Product Analysis
```
"Search for high and critical severity CVEs affecting Apache HTTP Server versions 2.4.x"
```
Claude will use:
```javascript
search_cves({
  keywordSearch: "Apache HTTP Server",
  cvssV3Severity: "HIGH",
  resultsPerPage: 50
})
// Note: You may need to do a second search for CRITICAL or use cpeName for version-specific queries
```

### Example 4: Incident Response
```
"Get complete details and change history for CVE-2021-44228 (Log4Shell)"
```
Claude will use both:
```javascript
get_cve_by_id({ cveId: "CVE-2021-44228" })
get_cve_change_history({ cveId: "CVE-2021-44228" })
```

### Example 5: Compliance Reporting
```
"List all CVEs published between January 1, 2024 and January 31, 2024 with CVSS v3 score above 9.0"
```
Claude will use:
```javascript
search_cves({
  pubStartDate: "2024-01-01T00:00:00.000Z",
  pubEndDate: "2024-01-31T23:59:59.999Z",
  cvssV3Severity: "CRITICAL",
  resultsPerPage: 100
})
```

## Advanced Features

### Using CVSS Vector Strings

You can search using specific CVSS vectors:

```
"Find CVEs with network attack vector, low complexity, and no privileges required"
```
Claude will use:
```javascript
search_cves({
  cvssV3Metrics: "AV:N/AC:L/PR:N"
})
```

### CPE Matching

For specific product versions:

```
"Find vulnerabilities affecting Windows 10 version 1607"
```
Claude will use:
```javascript
search_cves({
  cpeName: "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
})
```

### Exact Keyword Matching

For precise searches:

```
"Find CVEs mentioning exactly 'Remote Code Execution' in the description"
```
Claude will use:
```javascript
search_cves({
  keywordSearch: "Remote Code Execution",
  keywordExactMatch: true
})
```

## Troubleshooting

### Server Not Appearing in Claude

1. Check the configuration file path is correct
2. Ensure Node.js is in your PATH: `node --version`
3. Verify the server path in config matches your installation
4. Restart Claude completely (quit and reopen)
5. Check Claude logs for errors

### Rate Limiting

The NVD API has rate limits:
- **5 requests per 30 seconds** without API key
- **50 requests per 30 seconds** with API key (free from NVD)

If you hit rate limits, wait 30 seconds before trying again.

### Getting an API Key (Optional)

To increase rate limits:

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Request a free API key
3. Add it to `index.js` in the `makeNVDRequest` function:
   ```javascript
   url.searchParams.append('apiKey', 'YOUR_API_KEY_HERE');
   ```

## Next Steps

- **Test with simple queries** first
- **Combine with other MCP servers** for enhanced functionality
- **Automate security monitoring** by regularly checking for new CVEs
- **Create custom workflows** for your security operations

## Support

For issues or questions:
- Check the main README.md
- Review NVD API documentation
- Check MCP protocol documentation
- File an issue in the repository

Happy vulnerability hunting! 🔍🛡️
