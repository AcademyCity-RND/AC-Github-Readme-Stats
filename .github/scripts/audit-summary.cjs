const fs = require('fs');

function formatAuditReport(auditFile, outdatedFile, summaryOutputFile) {
  const markdown = [];
  markdown.push('# 🛡️ Dependency Security & Vulnerability Audit Report\n');

  // 1. Audit / CVE Scan
  if (fs.existsSync(auditFile)) {
    try {
      const rawAudit = fs.readFileSync(auditFile, 'utf8').trim();
      if (rawAudit) {
        const audit = JSON.parse(rawAudit);
        const counts = audit.metadata?.vulnerabilities || {};
        const total = counts.total || 0;

        markdown.push('## 1. Security Vulnerabilities (CVE Scan)\n');
        markdown.push('| Severity | Count | Status |');
        markdown.push('| :--- | :---: | :--- |');
        markdown.push(`| 🔴 **Critical** | ${counts.critical || 0} | ${(counts.critical || 0) > 0 ? '⚠️ Action Required' : '✅ Clear'} |`);
        markdown.push(`| 🟠 **High** | ${counts.high || 0} | ${(counts.high || 0) > 0 ? '⚠️ Action Required' : '✅ Clear'} |`);
        markdown.push(`| 🟡 **Moderate** | ${counts.moderate || 0} | ${(counts.moderate || 0) > 0 ? '⚠️ Warning' : '✅ Clear'} |`);
        markdown.push(`| 🔵 **Low** | ${counts.low || 0} | ${(counts.low || 0) > 0 ? 'ℹ️ Low Risk' : '✅ Clear'} |`);
        markdown.push(`| ℹ️ **Info** | ${counts.info || 0} | ${(counts.info || 0) > 0 ? 'ℹ️ Info' : '✅ Clear'} |`);
        markdown.push(`| **Total** | **${total}** | ${total === 0 ? '🎉 All clear!' : '🚨 Vulnerabilities detected'} |\n`);

        if (audit.vulnerabilities && Object.keys(audit.vulnerabilities).length > 0) {
          markdown.push('### 🚨 Vulnerable Packages Detail\n');
          markdown.push('| Package | Severity | Affected Range | Fix Available | Direct? | Advisories / Reference |');
          markdown.push('| :--- | :---: | :--- | :--- | :---: | :--- |');

          for (const [pkgName, item] of Object.entries(audit.vulnerabilities)) {
            const advisories = Array.isArray(item.via)
              ? item.via
                  .map((v) => (typeof v === 'object' ? `[${v.title || v.source || 'Advisory'}](${v.url || '#'})` : `via \`${v}\``))
                  .join('<br>')
              : 'N/A';

            let fixText = 'No automatic fix';
            if (item.fixAvailable === true) {
              fixText = '✅ `npm audit fix`';
            } else if (item.fixAvailable && typeof item.fixAvailable === 'object') {
              fixText = `⚠️ \`${item.fixAvailable.name}@${item.fixAvailable.version}\`${item.fixAvailable.isSemVerMajor ? ' *(Major)*' : ''}`;
            }

            markdown.push(`| **\`${pkgName}\`** | **${item.severity.toUpperCase()}** | \`${item.range || 'N/A'}\` | ${fixText} | ${item.isDirect ? 'Yes' : 'No'} | ${advisories || '-'} |`);
          }
          markdown.push('\n');
        }
      }
    } catch (err) {
      markdown.push(`> ⚠️ Could not parse audit JSON: ${err.message}\n`);
    }
  }

  // 2. Outdated Dependencies
  if (fs.existsSync(outdatedFile)) {
    try {
      const rawOutdated = fs.readFileSync(outdatedFile, 'utf8').trim();
      if (rawOutdated) {
        const outdated = JSON.parse(rawOutdated);
        const entries = Object.entries(outdated);

        markdown.push('## 2. Outdated Dependencies Check\n');
        if (entries.length === 0) {
          markdown.push('✅ All dependencies are up to date!\n');
        } else {
          markdown.push(`Found **${entries.length}** outdated package(s):\n`);
          markdown.push('| Package | Current | Wanted | Latest | Type |');
          markdown.push('| :--- | :---: | :---: | :---: | :--- |');
          for (const [pkg, info] of entries) {
            markdown.push(`| **\`${pkg}\`** | \`${info.current || 'N/A'}\` | \`${info.wanted || 'N/A'}\` | \`${info.latest || 'N/A'}\` | \`${info.type || 'dependencies'}\` |`);
          }
          markdown.push('\n');
        }
      }
    } catch (err) {
      markdown.push(`> ⚠️ Could not parse outdated JSON: ${err.message}\n`);
    }
  }

  const finalReport = markdown.join('\n');
  console.log(finalReport);

  const targetOutput = summaryOutputFile || process.env.GITHUB_STEP_SUMMARY;
  if (targetOutput) {
    fs.appendFileSync(targetOutput, finalReport + '\n');
  }
}

const auditFile = process.argv[2] || 'audit.json';
const outdatedFile = process.argv[3] || 'outdated.json';
const summaryOutput = process.argv[4] || process.env.GITHUB_STEP_SUMMARY;

formatAuditReport(auditFile, outdatedFile, summaryOutput);
