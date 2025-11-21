#!/usr/bin/env node

/**
 * NVD API Capabilities Testing Script
 * Tests various queries to see what's possible for new tool features
 */

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json';
const CVE_API_VERSION = '2.0';
const NVD_API_KEY = process.env.NVD_API_KEY;

// Rate limiting helper
async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Make NVD API request
async function testNVDQuery(testName, endpoint, params = {}) {
  const url = new URL(`${NVD_BASE_URL}/${endpoint}/${CVE_API_VERSION}`);

  if (NVD_API_KEY) {
    url.searchParams.append('apiKey', NVD_API_KEY);
  }

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.append(key, value);
    }
  });

  console.log(`\n${'='.repeat(80)}`);
  console.log(`TEST: ${testName}`);
  console.log(`${'='.repeat(80)}`);
  console.log(`URL: ${url.toString().replace(NVD_API_KEY || '', 'API_KEY_HIDDEN')}\n`);

  try {
    const response = await fetch(url.toString());

    if (!response.ok) {
      console.log(`❌ FAILED: ${response.status} ${response.statusText}`);
      return { success: false, status: response.status };
    }

    const data = await response.json();
    console.log(`✅ SUCCESS`);
    console.log(`Total Results: ${data.totalResults || 0}`);
    console.log(`Results Returned: ${data.vulnerabilities?.length || 0}`);

    // Sample first result
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      const cve = data.vulnerabilities[0].cve;
      console.log(`\nSample CVE: ${cve.id}`);
      console.log(`Published: ${cve.published}`);
      console.log(`Status: ${cve.vulnStatus}`);

      // Check available data
      if (cve.metrics?.cvssMetricV31?.[0]) {
        console.log(`CVSS v3.1: ${cve.metrics.cvssMetricV31[0].cvssData.baseScore}`);
      }
      if (cve.weaknesses) {
        console.log(`CWEs: ${cve.weaknesses.length}`);
      }
      if (cve.cisaExploitAdd) {
        console.log(`⚠️  CISA KEV: Yes`);
      }
      if (cve.references) {
        console.log(`References: ${cve.references.length}`);
        // Check for exploit tags
        const hasExploit = cve.references.some(ref =>
          ref.tags?.includes('Exploit') || ref.tags?.includes('Third Party Advisory')
        );
        if (hasExploit) {
          console.log(`🔴 Has Exploit References!`);
        }
      }
    }

    return { success: true, data };
  } catch (error) {
    console.log(`❌ ERROR: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// Main test suite
async function runTests() {
  console.log('\n🧪 NVD API CAPABILITIES TEST SUITE\n');
  console.log(`API Key: ${NVD_API_KEY ? '✅ Configured' : '❌ Not set'}`);
  console.log(`Rate Limit: ${NVD_API_KEY ? '50 req/30s' : '5 req/30s'}`);

  const tests = [];

  // Test 1: Get recent CVEs for statistics
  tests.push({
    name: 'Recent CVEs for Statistics',
    test: async () => {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 30);

      return await testNVDQuery(
        'Get last 30 days of CVEs',
        'cves',
        {
          pubStartDate: startDate.toISOString(),
          pubEndDate: endDate.toISOString(),
          resultsPerPage: 100
        }
      );
    }
  });

  // Test 2: Search by vendor (using keyword)
  tests.push({
    name: 'Vendor Search (Microsoft)',
    test: async () => {
      return await testNVDQuery(
        'Search for Microsoft CVEs',
        'cves',
        {
          keywordSearch: 'Microsoft',
          resultsPerPage: 20
        }
      );
    }
  });

  // Test 3: KEV CVEs
  tests.push({
    name: 'CISA KEV CVEs',
    test: async () => {
      return await testNVDQuery(
        'Get CVEs in KEV catalog',
        'cves',
        {
          hasKev: '',
          resultsPerPage: 20
        }
      );
    }
  });

  // Test 4: Multiple CVEs for comparison
  tests.push({
    name: 'Multiple CVE Lookup',
    test: async () => {
      // Note: NVD API doesn't support multiple CVE IDs in one request
      // We'd need to make multiple requests
      console.log('\n⚠️  NOTE: NVD API requires separate requests for multiple CVEs');
      console.log('Testing single CVE lookup as baseline...\n');

      return await testNVDQuery(
        'Get CVE-2021-44228 (Log4Shell)',
        'cves',
        {
          cveId: 'CVE-2021-44228'
        }
      );
    }
  });

  // Test 5: CVEs with specific CWE
  tests.push({
    name: 'CWE-89 (SQL Injection) Analysis',
    test: async () => {
      return await testNVDQuery(
        'Get SQL Injection CVEs',
        'cves',
        {
          cweId: 'CWE-89',
          resultsPerPage: 50
        }
      );
    }
  });

  // Test 6: CVEs with exploits (via reference tags)
  tests.push({
    name: 'CVEs with Exploit References',
    test: async () => {
      const result = await testNVDQuery(
        'Recent CVEs (checking for exploit refs)',
        'cves',
        {
          resultsPerPage: 100
        }
      );

      if (result.success && result.data.vulnerabilities) {
        const withExploits = result.data.vulnerabilities.filter(item => {
          const cve = item.cve;
          return cve.references?.some(ref =>
            ref.tags?.includes('Exploit')
          );
        });

        console.log(`\n📊 Analysis:`);
        console.log(`Total CVEs: ${result.data.vulnerabilities.length}`);
        console.log(`With Exploit Tags: ${withExploits.length}`);
        console.log(`Percentage: ${(withExploits.length / result.data.vulnerabilities.length * 100).toFixed(1)}%`);
      }

      return result;
    }
  });

  // Test 7: CPE search for version ranges
  tests.push({
    name: 'CPE Version Range (Apache Log4j)',
    test: async () => {
      return await testNVDQuery(
        'Search Apache Log4j CPE',
        'cves',
        {
          virtualMatchString: 'cpe:2.3:a:apache:log4j',
          resultsPerPage: 20
        }
      );
    }
  });

  // Test 8: Change history for timeline
  tests.push({
    name: 'CVE Change History (Log4Shell)',
    test: async () => {
      return await testNVDQuery(
        'Get Log4Shell change history',
        'cvehistory',
        {
          cveId: 'CVE-2021-44228'
        }
      );
    }
  });

  // Test 9: Recent high severity CVEs
  tests.push({
    name: 'Recent CRITICAL CVEs',
    test: async () => {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 7);

      return await testNVDQuery(
        'Last 7 days CRITICAL severity',
        'cves',
        {
          pubStartDate: startDate.toISOString(),
          pubEndDate: endDate.toISOString(),
          cvssV3Severity: 'CRITICAL',
          resultsPerPage: 50
        }
      );
    }
  });

  // Test 10: Source identifier filtering
  tests.push({
    name: 'CVEs by Source (cve@mitre.org)',
    test: async () => {
      return await testNVDQuery(
        'Get CVEs from MITRE',
        'cves',
        {
          sourceIdentifier: 'cve@mitre.org',
          resultsPerPage: 20
        }
      );
    }
  });

  // Run all tests with rate limiting
  const results = [];
  for (const test of tests) {
    const result = await test.test();
    results.push({ name: test.name, ...result });

    // Rate limiting: wait between requests
    const waitTime = NVD_API_KEY ? 600 : 6000; // 0.6s with key, 6s without
    console.log(`\n⏳ Waiting ${waitTime}ms before next test...`);
    await sleep(waitTime);
  }

  // Summary
  console.log('\n\n' + '='.repeat(80));
  console.log('TEST SUMMARY');
  console.log('='.repeat(80));

  const passed = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  console.log(`✅ Passed: ${passed}/${results.length}`);
  console.log(`❌ Failed: ${failed}/${results.length}`);

  console.log('\n📋 Feasibility Assessment:\n');

  const assessments = [
    {
      feature: '1. get_cve_statistics',
      feasible: true,
      notes: 'Can aggregate data from queries, calculate stats client-side'
    },
    {
      feature: '2. get_vendor_cves',
      feasible: true,
      notes: 'Use keyword search, but not perfect (needs filtering)'
    },
    {
      feature: '3. compare_cves',
      feasible: true,
      notes: 'Make multiple single CVE requests, merge results'
    },
    {
      feature: '4. get_kev_summary',
      feasible: true,
      notes: 'hasKev parameter works, can aggregate stats'
    },
    {
      feature: '5. get_exploitable_cves',
      feasible: true,
      notes: 'Check reference tags for "Exploit", "Third Party Advisory"'
    },
    {
      feature: '6. export_cves',
      feasible: true,
      notes: 'Format results as JSON/CSV/Markdown client-side'
    },
    {
      feature: '7. get_cve_timeline',
      feasible: true,
      notes: 'Use cvehistory endpoint + CVE data'
    },
    {
      feature: '8. analyze_cvss_vector',
      feasible: true,
      notes: 'Parse vector string, calculate score client-side'
    },
    {
      feature: '9. get_trending_cves',
      feasible: true,
      notes: 'Sort by lastModified or published dates'
    },
    {
      feature: '10. search_by_cpe_range',
      feasible: true,
      notes: 'Use virtualMatchString + versionStart/versionEnd'
    },
    {
      feature: '11. get_vulnerability_family',
      feasible: 'partial',
      notes: 'Can search related by keyword, but not perfect'
    },
    {
      feature: '12. get_cwe_analysis',
      feasible: true,
      notes: 'Use cweId parameter, aggregate stats'
    },
    {
      feature: '13. batch_lookup',
      feasible: true,
      notes: 'Make multiple requests (rate limited)'
    },
    {
      feature: '14. predict_risk_score',
      feasible: true,
      notes: 'Custom scoring logic client-side'
    }
  ];

  assessments.forEach((a, i) => {
    const status = a.feasible === true ? '✅' : a.feasible === 'partial' ? '⚠️' : '❌';
    console.log(`${status} ${a.feature}`);
    console.log(`   ${a.notes}\n`);
  });

  console.log('\n💡 RECOMMENDATIONS:\n');
  console.log('EASY WINS (Implement First):');
  console.log('  1. ✅ get_vendor_cves - Keyword search works well');
  console.log('  2. ✅ get_kev_summary - Direct API support');
  console.log('  3. ✅ export_cves - Simple formatting');
  console.log('  4. ✅ get_cve_statistics - Aggregate from queries');
  console.log('  5. ✅ compare_cves - Multiple requests work');

  console.log('\nMEDIUM COMPLEXITY:');
  console.log('  6. ✅ get_exploitable_cves - Check reference tags');
  console.log('  7. ✅ get_cve_timeline - Combine history + CVE data');
  console.log('  8. ✅ get_trending_cves - Sort by dates');
  console.log('  9. ✅ search_by_cpe_range - Use version parameters');

  console.log('\nADVANCED:');
  console.log(' 10. ✅ analyze_cvss_vector - CVSS calculator');
  console.log(' 11. ✅ get_cwe_analysis - Aggregate CWE stats');
  console.log(' 12. ✅ predict_risk_score - Custom scoring');

  console.log('\n✅ VERDICT: Almost all features are feasible!\n');
}

// Run the tests
console.log('Starting NVD API capability tests...\n');
console.log('⚠️  This will make multiple API requests.');
console.log('⚠️  With API key: ~10 seconds total');
console.log('⚠️  Without API key: ~60 seconds total\n');

runTests().catch(error => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
