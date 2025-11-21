# NVD MCP Server (Node.js)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-1.0.4-blue)](https://modelcontextprotocol.io)
[![NVD API](https://img.shields.io/badge/NVD%20API-v2.0-red)](https://nvd.nist.gov/developers/vulnerabilities)

A Model Context Protocol (MCP) server for querying the NIST National Vulnerability Database (NVD) API. This Node.js implementation provides comprehensive access to 300K+ CVE (Common Vulnerabilities and Exposures) records through Claude Code and other MCP clients.

**No Docker required** • **NPX compatible** • **4 powerful tools** • **API key support**

## Why This Implementation?

### Node.js/NPX vs Python/UVX

This project provides a **Node.js alternative** to the Python-based [mcp-nvd](https://github.com/marcoeg/mcp-nvd) implementation. Here's why you might prefer this version:

| Feature | Python (uvx) | This (Node.js/npx) | Advantage |
|---------|--------------|-------------------|-----------|
| **Number of Tools** | 2 tools | **4 tools** | 🏆 2x more functionality |
| **Docker Required** | Yes (for testing/deployment) | **No** | 🏆 Simpler setup |
| **API Key** | Required | **Optional** | 🏆 Works out of the box |
| **Change History** | ❌ Not available | **✅ Full history tracking** | 🏆 Better auditing |
| **Recent CVEs Helper** | ❌ Manual date queries | **✅ Built-in helper** | 🏆 Easier monitoring |
| **Setup Complexity** | Medium (Python + uv) | **Easy** (just Node.js) | 🏆 Lower barrier |
| **Concise Output** | ✅ Yes | ✅ Yes | 🤝 Parity |
| **Runtime** | Python 3.10+ | Node.js 18+ | 🤝 Both modern |
| **Package Manager** | uvx | **npx** | 🤝 Both standard |

### When to Use Node.js Version (This Repo)

✅ You already have Node.js in your environment
✅ You want more tools (change history, recent CVEs)
✅ You prefer simpler setup without Docker
✅ You want API key to be optional
✅ You need to integrate with Node.js projects

### When to Use Python Version

✅ You prefer Python ecosystem
✅ You need SSE (Server-Sent Events) transport
✅ You want Docker containerization
✅ You're already using uvx/uv tooling

### Tool Comparison

#### Python Version (2 tools):
1. `get_cve` - Get single CVE by ID
2. `search_cve` - Search CVEs by keyword

#### Node.js Version (4 tools):
1. `get_cve_by_id` - Get single CVE by ID with concise mode
2. `search_cves` - Search with **20+ parameters** (keywords, CVSS, CWE, dates, KEV, CPE, etc.)
3. `get_cve_change_history` - **Track modifications** over time
4. `search_recent_cves` - **Quick helper** for last N days

### Architecture Differences

| Aspect | Python Implementation | Node.js Implementation |
|--------|----------------------|----------------------|
| Transport | stdio + SSE | **stdio** (simpler) |
| Framework | FastAPI concepts | **Native Node.js** |
| Containerization | Docker + Compose | **None needed** |
| Testing | Docker-based | **Direct execution** |
| Deployment | Container or uvx | **npx or direct node** |
| Configuration | Environment + config | **Environment only** |

## Features

- **Search CVEs**: Query vulnerabilities with extensive filtering options
- **Get CVE by ID**: Retrieve detailed information about specific CVEs
- **Change History**: Track modifications to CVE records over time
- **Recent CVEs**: Quickly find recently published or modified vulnerabilities
- **CISA KEV Integration**: Filter for Known Exploited Vulnerabilities
- **CVSS Scoring**: Search by CVSSv2, CVSSv3, or CVSSv4 metrics
- **CWE Mapping**: Filter by Common Weakness Enumeration IDs

## Installation

### Prerequisites

- Node.js 18.0.0 or higher
- npm or yarn

### Install Dependencies

```bash
cd nvd-mcp-server
npm install
```

## Configuration

### For Claude Code (Desktop)

Add the following to your Claude Code MCP configuration file:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Linux**: `~/.config/Claude/claude_desktop_config.json`

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

**Note**: Update the path to match your actual installation location and add your NVD API key.

### For Claude Code CLI

If using Claude Code in the terminal, add the server:

```bash
# Set your API key (optional but recommended)
export NVD_API_KEY="YOUR_NVD_API_KEY_HERE"

# Add the MCP server
claude mcp add nvd node /path/to/nvd-mcp-server/index.js
```

After adding the configuration, restart Claude Code to load the MCP server.

## Usage

Once configured, you can use the NVD MCP server through Claude Code with natural language queries:

### Example Queries

#### Search for Recent Critical CVEs
```
"Show me critical CVEs from the last 7 days"
```

#### Search by Keyword
```
"Find CVEs related to Apache Log4j"
```

#### Get Specific CVE
```
"Get details for CVE-2021-44228"
```

#### Search by CVSS Score
```
"Show high severity CVEs affecting Windows"
```

#### CISA KEV Vulnerabilities
```
"List all CVEs in the CISA Known Exploited Vulnerabilities catalog"
```

#### Search by CWE
```
"Find CVEs related to SQL injection (CWE-89)"
```

## Available Tools

### 1. `search_cves`

Search the NVD database with comprehensive filtering options.

**Parameters:**
- `cveId` (string): Specific CVE ID (e.g., CVE-2021-44228)
- `cpeName` (string): CPE name for product filtering
- `keywordSearch` (string): Keywords in CVE descriptions
- `keywordExactMatch` (boolean): Exact phrase matching
- `cvssV3Severity` (string): LOW, MEDIUM, HIGH, or CRITICAL
- `cvssV3Metrics` (string): CVSSv3 vector string
- `cvssV2Severity` (string): LOW, MEDIUM, or HIGH
- `cvssV2Metrics` (string): CVSSv2 vector string
- `cweId` (string): CWE identifier (e.g., CWE-287)
- `hasKev` (boolean): Filter for CISA KEV entries
- `hasCertAlerts` (boolean): Filter for US-CERT alerts
- `hasCertNotes` (boolean): Filter for CERT/CC notes
- `hasOval` (boolean): Filter for OVAL information
- `pubStartDate` (string): Published start date (ISO-8601)
- `pubEndDate` (string): Published end date (ISO-8601)
- `lastModStartDate` (string): Last modified start date
- `lastModEndDate` (string): Last modified end date
- `sourceIdentifier` (string): Source identifier
- `noRejected` (boolean): Exclude rejected CVEs
- `resultsPerPage` (number): Results per page (max 2000)
- `startIndex` (number): Pagination offset

### 2. `get_cve_by_id`

Retrieve detailed information about a specific CVE.

**Parameters:**
- `cveId` (string, required): The CVE ID to retrieve

### 3. `get_cve_change_history`

View the change history for CVEs.

**Parameters:**
- `cveId` (string): Specific CVE ID
- `changeStartDate` (string): Change start date (ISO-8601)
- `changeEndDate` (string): Change end date (ISO-8601)
- `eventName` (string): Type of change event
- `resultsPerPage` (number): Results per page (max 5000)
- `startIndex` (number): Pagination offset

### 4. `search_recent_cves`

Quick search for recently published or modified CVEs.

**Parameters:**
- `days` (number): Days to look back (default: 7, max: 120)
- `type` (string): "published" or "modified"
- `severity` (string): Optional CVSSv3 severity filter
- `hasKev` (boolean): Optional KEV catalog filter
- `resultsPerPage` (number): Results per page

## API Rate Limits

The NVD API has rate limits:
- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds (10x faster!)

### Getting an API Key (Free)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Request a free API key (delivered instantly via email)
3. Add it to your MCP configuration as shown above

The server automatically uses the `NVD_API_KEY` environment variable when available.

## Response Format

The server returns formatted text with:
- CVE ID and basic metadata
- Publication and modification dates
- Vulnerability status
- English description
- CVSS scores (v2, v3, v4 when available)
- CWE weaknesses
- CISA KEV status (if applicable)
- References with tags

## Examples

### Search for Log4j Vulnerabilities
```javascript
// Claude will call:
search_cves({
  keywordSearch: "log4j",
  cvssV3Severity: "CRITICAL",
  resultsPerPage: 10
})
```

### Get CVE Details
```javascript
// Claude will call:
get_cve_by_id({
  cveId: "CVE-2021-44228"
})
```

### Recent KEV Entries
```javascript
// Claude will call:
search_recent_cves({
  days: 30,
  type: "modified",
  hasKev: true
})
```

## Troubleshooting

### Server Not Starting
- Ensure Node.js 18+ is installed: `node --version`
- Check dependencies are installed: `npm install`
- Verify the path in your configuration is correct

### No Results Returned
- Check your query parameters
- NVD API may be temporarily unavailable
- Rate limits may be exceeded (wait 30 seconds)

### Connection Issues
- Ensure you have internet connectivity
- Check if https://services.nvd.nist.gov is accessible
- Verify firewall settings allow outbound HTTPS

## Development

### Testing the Server Standalone

```bash
# Run the server directly
node index.js

# The server uses stdio transport, so it expects MCP protocol messages
```

### Adding an API Key

To increase rate limits, obtain a free API key from NVD and modify `index.js`:

```javascript
async function makeNVDRequest(endpoint, params = {}) {
  const url = new URL(`${NVD_BASE_URL}/${endpoint}/${CVE_API_VERSION}`);

  // Add your API key
  url.searchParams.append('apiKey', 'YOUR_API_KEY_HERE');

  // ... rest of the function
}
```

## Resources

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [MCP Documentation](https://modelcontextprotocol.io)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CVE Program](https://www.cve.org/)
- [CVSS Calculator](https://nvd.nist.gov/vuln-metrics/cvss)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Disclaimer

This tool queries public NVD data. Always verify vulnerability information from official sources before taking action. The NVD database is maintained by NIST and includes data from CVE, CVSS, CWE, and other sources.
