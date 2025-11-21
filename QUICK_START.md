# NVD MCP Server - Quick Start Guide

## ✅ Setup Complete!

Your NVD MCP server is configured and ready to use in VSCode with Claude Code.

### 📍 Configuration Location
```
.claude/mcp_settings.json
```

### 🔑 API Key Status
To get your free API key:
1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Add it to your configuration

With API key: **50 requests per 30 seconds**
Without API key: 5 requests per 30 seconds

## 🚀 Quick Test Commands

### 1. Test Basic Functionality
Ask Claude:
```
"List the 5 most recent critical CVEs"
```

### 2. Test Search by Keyword
```
"Search for CVEs related to Apache"
```

### 3. Test Specific CVE Lookup
```
"Get details for CVE-2021-44228"
```

### 4. Test CISA KEV Filter
```
"Show me CVEs in CISA's Known Exploited Vulnerabilities catalog from the last 30 days"
```

### 5. Test Concise Mode
```
"Show me 20 critical CVEs in concise format"
```

## 📋 Available Tools

| Tool | Description | Example |
|------|-------------|---------|
| **search_cves** | Search with filters | "Find high severity CVEs in Windows" |
| **get_cve_by_id** | Get specific CVE | "Show CVE-2024-12345" |
| **get_cve_change_history** | Track changes | "Show change history for CVE-2021-44228" |
| **search_recent_cves** | Recent vulns | "Critical CVEs from last 7 days" |

## 🎛️ Advanced Features

### Concise Output Mode
Add "in concise format" to any query:
```
"Search for SQL injection CVEs in concise format"
```

### Date Range Queries
```
"Show CVEs published between January 1, 2024 and January 31, 2024"
```

### CVSS Filtering
```
"Find all CRITICAL severity CVEs affecting Microsoft products"
```

### CWE (Weakness) Filtering
```
"Show all CVEs related to CWE-89 (SQL Injection)"
```

### CPE (Product) Filtering
```
"Find vulnerabilities in Windows 10 version 1607"
```

## 🔧 Troubleshooting

### Server Not Starting
1. Check Node.js is installed: `node --version` (need 20+)
2. Verify dependencies: `cd G:\ai_ghost_chat\nvd-mcp-server && npm install`
3. Restart VSCode

### Rate Limit Errors
- With API key: 50 requests/30s
- Wait 30 seconds if you hit the limit
- Consider spacing out large queries

### No Results
- Verify internet connection
- Check NVD API status: https://nvd.nist.gov/
- Try a broader search query

## 📚 Full Documentation

- **README.md** - Complete feature documentation
- **CLAUDE_CODE_SETUP.md** - Detailed setup guide with all parameters
- **index.js** - Source code with inline comments

## 🌟 Example Workflows

### Security Monitoring Workflow
```
1. "Show me CVEs added to CISA KEV in the last 7 days"
2. "Get detailed info for each high priority CVE"
3. "Check change history to see if severity changed"
```

### Vulnerability Research Workflow
```
1. "Search for all critical CVEs in Apache products"
2. "Filter by CVEs from 2024 only"
3. "Show me the CWE categories for these vulnerabilities"
```

### Compliance Reporting Workflow
```
1. "Get all CVEs published in Q1 2024"
2. "Filter for HIGH and CRITICAL severity only"
3. "Export in concise format for reporting"
```

## 🎯 Pro Tips

1. **Use concise mode** for scanning large result sets
2. **Combine filters** for precise results (severity + date + keyword)
3. **Check KEV regularly** for actively exploited vulnerabilities
4. **Set up date ranges** to stay current (last 7/30 days)
5. **Use CWE filters** to track specific vulnerability types

## 🆘 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review the full documentation in README.md
3. Verify your API key is valid
4. Check NVD API status

## 🎉 You're Ready!

Your NVD MCP server is fully configured with:
- ✅ API key for fast rate limits
- ✅ All 4 tools available
- ✅ Concise mode support
- ✅ Full NVD API v2.0 coverage

Start querying vulnerabilities with Claude Code now!
