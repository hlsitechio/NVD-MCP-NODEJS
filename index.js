#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json';
const CVE_API_VERSION = '2.0';
const NVD_API_KEY = process.env.NVD_API_KEY;

/**
 * Make a request to the NVD API with rate limiting consideration
 */
async function makeNVDRequest(endpoint, params = {}) {
  const url = new URL(`${NVD_BASE_URL}/${endpoint}/${CVE_API_VERSION}`);

  // Add API key if available (increases rate limit from 5 to 50 requests per 30 seconds)
  if (NVD_API_KEY) {
    url.searchParams.append('apiKey', NVD_API_KEY);
  }

  // Add query parameters
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.append(key, value);
    }
  });

  try {
    const response = await fetch(url.toString());

    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('NVD API rate limit exceeded. Please wait 30 seconds or add an API key.');
      }
      throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`Failed to fetch from NVD API: ${error.message}`);
  }
}

/**
 * Format CVE data for display
 */
function formatCVEData(data, concise = false) {
  const { resultsPerPage, startIndex, totalResults, vulnerabilities } = data;

  if (!vulnerabilities || vulnerabilities.length === 0) {
    return 'No vulnerabilities found matching the criteria.';
  }

  let result = `Found ${totalResults} total results (showing ${vulnerabilities.length} from index ${startIndex})\n\n`;

  vulnerabilities.forEach((item, index) => {
    const cve = item.cve;

    if (concise) {
      // Concise format: one-line summary per CVE
      result += `${cve.id} | `;

      // Get CVSS score
      let cvssScore = 'N/A';
      let severity = 'N/A';
      if (cve.metrics?.cvssMetricV31?.[0]) {
        cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity;
      } else if (cve.metrics?.cvssMetricV30?.[0]) {
        cvssScore = cve.metrics.cvssMetricV30[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity;
      } else if (cve.metrics?.cvssMetricV2?.[0]) {
        cvssScore = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV2[0].baseSeverity;
      }

      result += `CVSS: ${cvssScore} (${severity}) | `;

      // Get short description (first 100 chars)
      if (cve.descriptions?.[0]) {
        const desc = cve.descriptions.find(d => d.lang === 'en') || cve.descriptions[0];
        const shortDesc = desc.value.length > 100 ? desc.value.substring(0, 97) + '...' : desc.value;
        result += shortDesc;
      }

      if (cve.cisaExploitAdd) {
        result += ` [⚠️  KEV]`;
      }

      result += `\n`;
    } else {
      // Full format
      result += `\n${'='.repeat(80)}\n`;
      result += `[${startIndex + index + 1}] ${cve.id}\n`;
      result += `${'='.repeat(80)}\n`;
      result += `Published: ${cve.published}\n`;
      result += `Last Modified: ${cve.lastModified}\n`;
      result += `Status: ${cve.vulnStatus}\n`;

      // Description
      if (cve.descriptions && cve.descriptions.length > 0) {
        const engDesc = cve.descriptions.find(d => d.lang === 'en');
        if (engDesc) {
          result += `\nDescription:\n${engDesc.value}\n`;
        }
      }

      // CVSS Metrics
      if (cve.metrics) {
        result += `\nCVSS Scores:\n`;

        // CVSSv3.1
        if (cve.metrics.cvssMetricV31 && cve.metrics.cvssMetricV31.length > 0) {
          const cvss = cve.metrics.cvssMetricV31[0];
          result += `  CVSSv3.1: ${cvss.cvssData.baseScore} (${cvss.cvssData.baseSeverity})\n`;
          result += `    Vector: ${cvss.cvssData.vectorString}\n`;
        }

        // CVSSv3.0
        if (cve.metrics.cvssMetricV30 && cve.metrics.cvssMetricV30.length > 0) {
          const cvss = cve.metrics.cvssMetricV30[0];
          result += `  CVSSv3.0: ${cvss.cvssData.baseScore} (${cvss.cvssData.baseSeverity})\n`;
          result += `    Vector: ${cvss.cvssData.vectorString}\n`;
        }

        // CVSSv2
        if (cve.metrics.cvssMetricV2 && cve.metrics.cvssMetricV2.length > 0) {
          const cvss = cve.metrics.cvssMetricV2[0];
          result += `  CVSSv2: ${cvss.cvssData.baseScore} (${cvss.baseSeverity})\n`;
          result += `    Vector: ${cvss.cvssData.vectorString}\n`;
        }
      }

      // CWE
      if (cve.weaknesses && cve.weaknesses.length > 0) {
        result += `\nWeaknesses (CWE):\n`;
        cve.weaknesses.forEach(weakness => {
          weakness.description.forEach(desc => {
            result += `  - ${desc.value}\n`;
          });
        });
      }

      // KEV Status
      if (cve.cisaExploitAdd) {
        result += `\n⚠️  CISA KEV: This vulnerability is in CISA's Known Exploited Vulnerabilities catalog\n`;
        result += `    Added: ${cve.cisaExploitAdd}\n`;
        result += `    Action Due: ${cve.cisaActionDue}\n`;
        result += `    Required Action: ${cve.cisaRequiredAction}\n`;
      }

      // References
      if (cve.references && cve.references.length > 0) {
        result += `\nReferences:\n`;
        cve.references.slice(0, 5).forEach(ref => {
          result += `  - ${ref.url}`;
          if (ref.tags && ref.tags.length > 0) {
            result += ` [${ref.tags.join(', ')}]`;
          }
          result += `\n`;
        });
        if (cve.references.length > 5) {
          result += `  ... and ${cve.references.length - 5} more references\n`;
        }
      }
    }
  });

  return result;
}

/**
 * Format CVE change history data
 */
function formatChangeHistoryData(data) {
  const { resultsPerPage, startIndex, totalResults, cveChanges } = data;

  if (!cveChanges || cveChanges.length === 0) {
    return 'No change history found matching the criteria.';
  }

  let result = `Found ${totalResults} total change events (showing ${cveChanges.length} from index ${startIndex})\n\n`;

  cveChanges.forEach((item, index) => {
    const change = item.change;
    result += `\n${'='.repeat(80)}\n`;
    result += `[${startIndex + index + 1}] ${change.cveId} - ${change.eventName}\n`;
    result += `${'='.repeat(80)}\n`;
    result += `Change ID: ${change.cveChangeId}\n`;
    result += `Source: ${change.sourceIdentifier}\n`;
    result += `Date: ${change.created}\n`;

    if (change.details && change.details.length > 0) {
      result += `\nDetails:\n`;
      change.details.forEach(detail => {
        result += `  ${detail.action} - ${detail.type}\n`;
        if (detail.oldValue) {
          result += `    Old: ${detail.oldValue}\n`;
        }
        if (detail.newValue) {
          result += `    New: ${detail.newValue}\n`;
        }
      });
    }
  });

  return result;
}

// Create server instance
const server = new Server(
  {
    name: 'nvd-mcp-server',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'search_cves',
        description: 'Search the NVD database for CVEs with various filters including keywords, CVSS scores, dates, CPE names, CWE IDs, and more. Returns detailed vulnerability information.',
        inputSchema: {
          type: 'object',
          properties: {
            cveId: {
              type: 'string',
              description: 'Specific CVE ID (e.g., CVE-2021-44228)'
            },
            cpeName: {
              type: 'string',
              description: 'CPE name to search for (e.g., cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*)'
            },
            keywordSearch: {
              type: 'string',
              description: 'Keywords to search in CVE descriptions (space-separated for AND logic)'
            },
            keywordExactMatch: {
              type: 'boolean',
              description: 'If true, search for exact phrase match (requires keywordSearch)'
            },
            cvssV3Severity: {
              type: 'string',
              enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
              description: 'Filter by CVSSv3 severity rating'
            },
            cvssV3Metrics: {
              type: 'string',
              description: 'CVSSv3 vector string (e.g., AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)'
            },
            cvssV2Severity: {
              type: 'string',
              enum: ['LOW', 'MEDIUM', 'HIGH'],
              description: 'Filter by CVSSv2 severity rating'
            },
            cvssV2Metrics: {
              type: 'string',
              description: 'CVSSv2 vector string'
            },
            cweId: {
              type: 'string',
              description: 'CWE ID (e.g., CWE-287 for Improper Authentication)'
            },
            hasKev: {
              type: 'boolean',
              description: 'Only return CVEs in CISA Known Exploited Vulnerabilities catalog'
            },
            hasCertAlerts: {
              type: 'boolean',
              description: 'Only return CVEs with US-CERT alerts'
            },
            hasCertNotes: {
              type: 'boolean',
              description: 'Only return CVEs with CERT/CC notes'
            },
            hasOval: {
              type: 'boolean',
              description: 'Only return CVEs with OVAL information'
            },
            pubStartDate: {
              type: 'string',
              description: 'Published start date (ISO-8601 format: YYYY-MM-DDTHH:MM:SS.000Z)'
            },
            pubEndDate: {
              type: 'string',
              description: 'Published end date (ISO-8601 format, max 120 days range)'
            },
            lastModStartDate: {
              type: 'string',
              description: 'Last modified start date (ISO-8601 format)'
            },
            lastModEndDate: {
              type: 'string',
              description: 'Last modified end date (ISO-8601 format, max 120 days range)'
            },
            sourceIdentifier: {
              type: 'string',
              description: 'Source identifier (e.g., cve@mitre.org)'
            },
            noRejected: {
              type: 'boolean',
              description: 'Exclude rejected CVEs'
            },
            resultsPerPage: {
              type: 'number',
              description: 'Number of results per page (max 2000, default 2000)',
              default: 20
            },
            startIndex: {
              type: 'number',
              description: 'Starting index for pagination (0-based)',
              default: 0
            },
            concise: {
              type: 'boolean',
              description: 'Return concise one-line summaries instead of full details (default: false)',
              default: false
            }
          }
        }
      },
      {
        name: 'get_cve_by_id',
        description: 'Retrieve detailed information about a specific CVE by its ID (e.g., CVE-2021-44228)',
        inputSchema: {
          type: 'object',
          properties: {
            cveId: {
              type: 'string',
              description: 'The CVE ID to retrieve (e.g., CVE-2021-44228)'
            },
            concise: {
              type: 'boolean',
              description: 'Return concise one-line summary instead of full details (default: false)',
              default: false
            }
          },
          required: ['cveId']
        }
      },
      {
        name: 'get_cve_change_history',
        description: 'Retrieve the change history for CVEs, showing when and how vulnerabilities were modified',
        inputSchema: {
          type: 'object',
          properties: {
            cveId: {
              type: 'string',
              description: 'Specific CVE ID to get change history for'
            },
            changeStartDate: {
              type: 'string',
              description: 'Change start date (ISO-8601 format: YYYY-MM-DDTHH:MM:SS.000Z)'
            },
            changeEndDate: {
              type: 'string',
              description: 'Change end date (ISO-8601 format, max 120 days range)'
            },
            eventName: {
              type: 'string',
              enum: [
                'CVE Received',
                'Initial Analysis',
                'Reanalysis',
                'CVE Modified',
                'Modified Analysis',
                'CVE Translated',
                'Vendor Comment',
                'CVE Source Update',
                'CPE Deprecation Remap',
                'CWE Remap',
                'Reference Tag Update',
                'CVE Rejected',
                'CVE Unrejected',
                'CVE CISA KEV Update'
              ],
              description: 'Type of change event to filter by'
            },
            resultsPerPage: {
              type: 'number',
              description: 'Number of results per page (max 5000, default 100)',
              default: 100
            },
            startIndex: {
              type: 'number',
              description: 'Starting index for pagination (0-based)',
              default: 0
            }
          }
        }
      },
      {
        name: 'search_recent_cves',
        description: 'Quick search for recently published or modified CVEs within the last N days',
        inputSchema: {
          type: 'object',
          properties: {
            days: {
              type: 'number',
              description: 'Number of days to look back (default: 7, max: 120)',
              default: 7
            },
            type: {
              type: 'string',
              enum: ['published', 'modified'],
              description: 'Search by published date or last modified date',
              default: 'published'
            },
            severity: {
              type: 'string',
              enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
              description: 'Optional: Filter by CVSSv3 severity'
            },
            hasKev: {
              type: 'boolean',
              description: 'Optional: Only show CVEs in CISA KEV catalog'
            },
            resultsPerPage: {
              type: 'number',
              description: 'Number of results (default: 20)',
              default: 20
            }
          }
        }
      }
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'search_cves': {
        const params = {};

        // Map all possible parameters
        if (args.cveId) params.cveId = args.cveId;
        if (args.cpeName) params.cpeName = args.cpeName;
        if (args.keywordSearch) params.keywordSearch = args.keywordSearch;
        if (args.keywordExactMatch) params.keywordExactMatch = '';
        if (args.cvssV3Severity) params.cvssV3Severity = args.cvssV3Severity;
        if (args.cvssV3Metrics) params.cvssV3Metrics = args.cvssV3Metrics;
        if (args.cvssV2Severity) params.cvssV2Severity = args.cvssV2Severity;
        if (args.cvssV2Metrics) params.cvssV2Metrics = args.cvssV2Metrics;
        if (args.cweId) params.cweId = args.cweId;
        if (args.hasKev) params.hasKev = '';
        if (args.hasCertAlerts) params.hasCertAlerts = '';
        if (args.hasCertNotes) params.hasCertNotes = '';
        if (args.hasOval) params.hasOval = '';
        if (args.pubStartDate) params.pubStartDate = args.pubStartDate;
        if (args.pubEndDate) params.pubEndDate = args.pubEndDate;
        if (args.lastModStartDate) params.lastModStartDate = args.lastModStartDate;
        if (args.lastModEndDate) params.lastModEndDate = args.lastModEndDate;
        if (args.sourceIdentifier) params.sourceIdentifier = args.sourceIdentifier;
        if (args.noRejected) params.noRejected = '';
        if (args.resultsPerPage) params.resultsPerPage = args.resultsPerPage;
        if (args.startIndex) params.startIndex = args.startIndex;

        const data = await makeNVDRequest('cves', params);
        const formatted = formatCVEData(data, args.concise || false);

        return {
          content: [
            {
              type: 'text',
              text: formatted,
            },
          ],
        };
      }

      case 'get_cve_by_id': {
        if (!args.cveId) {
          throw new Error('cveId is required');
        }

        const data = await makeNVDRequest('cves', { cveId: args.cveId });
        const formatted = formatCVEData(data, args.concise || false);

        return {
          content: [
            {
              type: 'text',
              text: formatted,
            },
          ],
        };
      }

      case 'get_cve_change_history': {
        const params = {};

        if (args.cveId) params.cveId = args.cveId;
        if (args.changeStartDate) params.changeStartDate = args.changeStartDate;
        if (args.changeEndDate) params.changeEndDate = args.changeEndDate;
        if (args.eventName) params.eventName = args.eventName;
        if (args.resultsPerPage) params.resultsPerPage = args.resultsPerPage;
        if (args.startIndex) params.startIndex = args.startIndex;

        const data = await makeNVDRequest('cvehistory', params);
        const formatted = formatChangeHistoryData(data);

        return {
          content: [
            {
              type: 'text',
              text: formatted,
            },
          ],
        };
      }

      case 'search_recent_cves': {
        const days = args.days || 7;
        const type = args.type || 'published';

        if (days > 120) {
          throw new Error('Maximum lookback period is 120 days');
        }

        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);

        const params = {
          resultsPerPage: args.resultsPerPage || 20,
          startIndex: 0
        };

        if (type === 'published') {
          params.pubStartDate = startDate.toISOString();
          params.pubEndDate = endDate.toISOString();
        } else {
          params.lastModStartDate = startDate.toISOString();
          params.lastModEndDate = endDate.toISOString();
        }

        if (args.severity) params.cvssV3Severity = args.severity;
        if (args.hasKev) params.hasKev = '';

        const data = await makeNVDRequest('cves', params);
        const formatted = formatCVEData(data);

        return {
          content: [
            {
              type: 'text',
              text: formatted,
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('NVD MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
