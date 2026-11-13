document.addEventListener('DOMContentLoaded', () => {
  const openFileBtn = document.getElementById('openFileBtn');
  const singleFileInput = document.getElementById('singleFileInput');
  const openDirBtn = document.getElementById('openDirBtn');
  const dirInput = document.getElementById('dirInput');
  const fileInfo = document.getElementById('fileInfo');
  const summarySection = document.getElementById('summarySection');
  const warningsWrapper = document.getElementById('warningsWrapper');
  const resultTable = document.getElementById('resultTable');
  const tableHeaderRow = document.getElementById('tableHeaderRow');
  const tableBody = document.getElementById('tableBody');
  const detailNav = document.getElementById('detailNav');
  const backToOverviewBtn = document.getElementById('backToOverviewBtn');
  const detailTitle = document.getElementById('detailTitle');
  const rawDetails = document.getElementById('rawDetails');
  const output = document.getElementById('output');

  let directoryCache = {};

  openFileBtn.addEventListener('click', () => singleFileInput.click());
  openDirBtn.addEventListener('click', () => dirInput.click());
  backToOverviewBtn.addEventListener('click', () => renderOverviewTable());

  function getText(parent, tagName, fallback = '–') {
    if (!parent) return fallback;
    const el = parent.getElementsByTagName(tagName)[0];
    return el && el.textContent ? el.textContent.trim() : fallback;
  }

  function createBadge(value) {
    if (!value) value = 'none';
    const val = value.toLowerCase();
    let cls = 'neutral';
    if (val === 'pass') cls = 'pass';
    else if (val === 'fail' || val === 'reject' || val === 'quarantine') cls = 'fail';
    return `<span class="badge ${cls}">${value}</span>`;
  }

  function formatUnixDate(unixStr) {
    const ts = parseInt(unixStr, 10);
    if (isNaN(ts)) return '–';
    return new Date(ts * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }

  function compareIPs(ipA, ipB) {
    const parseIPv4 = (ip) => {
      if (!ip.includes('.')) return null;
      const parts = ip.split('.').map(Number);
      if (parts.length === 4 && parts.every(p => !isNaN(p))) return parts;
      return null;
    };
    const v4A = parseIPv4(ipA);
    const v4B = parseIPv4(ipB);
    if (v4A && v4B) {
      for (let i = 0; i < 4; i++) {
        if (v4A[i] !== v4B[i]) return v4A[i] - v4B[i];
      }
      return 0;
    }
    return ipA.localeCompare(ipB);
  }

  function parseRecordNode(record) {
    const row = record.getElementsByTagName('row')[0];
    const identifiers = record.getElementsByTagName('identifiers')[0];
    const authResults = record.getElementsByTagName('auth_results')[0];
    const policyEval = row ? row.getElementsByTagName('policy_evaluated')[0] : null;

    const sourceIp = getText(row, 'source_ip');
    const count = parseInt(getText(row, 'count', '0'), 10);
    const disposition = getText(policyEval, 'disposition', 'none');

    const spfAligned = getText(policyEval, 'spf', 'fail');
    const dkimAligned = getText(policyEval, 'dkim', 'fail');
    const dmarcPassed = (dkimAligned === 'pass' || spfAligned === 'pass') ? 'pass' : 'fail';

    const headerFrom = getText(identifiers, 'header_from');

    const spfNode = authResults ? authResults.getElementsByTagName('spf')[0] : null;
    const rawSpfResult = getText(spfNode, 'result', 'none');

    const dkimNodes = authResults ? Array.from(authResults.getElementsByTagName('dkim')) : [];
    let rawDkimResult = 'none';
    if (dkimNodes.length > 0) {
      const results = dkimNodes.map(n => getText(n, 'result', 'none').toLowerCase());
      rawDkimResult = results.includes('pass') ? 'pass' : results[0];
    }

    return {
      sourceIp,
      count,
      headerFrom,
      disposition,
      dmarcPassed,
      rawSpfResult,
      spfAligned,
      rawDkimResult,
      dkimAligned
    };
  }

  function aggregateRecords(records) {
    const map = new Map();

    records.forEach(rec => {
      const key = [
        rec.sourceIp,
        rec.headerFrom,
        rec.disposition,
        rec.dmarcPassed,
        rec.rawSpfResult,
        rec.spfAligned,
        rec.rawDkimResult,
        rec.dkimAligned
      ].join('|');

      if (map.has(key)) {
        map.get(key).count += rec.count;
      } else {
        map.set(key, { ...rec });
      }
    });

    return Array.from(map.values());
  }

  // --- Utökad och robust MSG-parser ---
  async function parseMsgFile(arrayBuffer) {
    const uint8 = new Uint8Array(arrayBuffer);
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const fullText = decoder.decode(arrayBuffer);
    
    // 1. Kolla om XML ligger direkt i textströmmen
    const xmlMatch = fullText.match(/<\?xml[\s\S]*<\/feedback>/i) || fullText.match(/<feedback[\s\S]*<\/feedback>/i);
    if (xmlMatch) return xmlMatch[0];

    // 2. Avancerad GZIP-sökning som hanterar OLE-block och trailing bytes
    for (let i = 0; i < uint8.length - 4; i++) {
      if (uint8[i] === 0x1f && uint8[i+1] === 0x8b) {
        // Testa att packa upp med reducerade chunk-storlekar om den stöter på skräp i slutet
        for (let len = uint8.length - i; len > 100; len -= 512) {
          try {
            const inflated = pako.inflate(uint8.slice(i, i + len), { to: 'string' });
            if (inflated && (inflated.includes('<feedback>') || inflated.includes('<?xml'))) {
              return inflated;
            }
          } catch (e) {
            // Fortsätt korta ner eller hoppa vidare
          }
        }
        // Fallback: prova hela resten av filen direkt
        try {
          const inflated = pako.inflate(uint8.slice(i), { to: 'string' });
          if (inflated && (inflated.includes('<feedback>') || inflated.includes('<?xml'))) {
            return inflated;
          }
        } catch (e) {}
      }
    }

    // 3. Kolla efter inbäddade ZIP-arkiv
    for (let i = 0; i < uint8.length - 4; i++) {
      if (uint8[i] === 0x50 && uint8[i+1] === 0x4b && uint8[i+2] === 0x03 && uint8[i+3] === 0x04) {
        try {
          const zip = new JSZip();
          const zipContent = await zip.loadAsync(uint8.slice(i));
          const xmlFilename = Object.keys(zipContent.files).find(name => name.toLowerCase().endsWith('.xml'));
          if (xmlFilename) {
            return await zipContent.files[xmlFilename].async('string');
          }
        } catch (e) {}
      }
    }

    throw new Error('Could not extract valid DMARC XML from .msg file structure.');
  }

  async function extractXmlFromFile(file) {
    const filename = file.name.toLowerCase();
    const arrayBuffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);

    if (filename.endsWith('.gz') || (uint8Array.length > 2 && uint8Array[0] === 0x1f && uint8Array[1] === 0x8b)) {
      return pako.inflate(uint8Array, { to: 'string' });
    }
    if (filename.endsWith('.zip') || (uint8Array.length > 2 && uint8Array[0] === 0x50 && uint8Array[1] === 0x4b)) {
      const zip = new JSZip();
      const zipContent = await zip.loadAsync(arrayBuffer);
      const xmlFilename = Object.keys(zipContent.files).find(name => name.toLowerCase().endsWith('.xml'));
      if (!xmlFilename) throw new Error('No XML file found inside ZIP archive.');
      return await zipContent.files[xmlFilename].async('string');
    }
    if (filename.endsWith('.eml')) {
      const emlText = new TextDecoder().decode(arrayBuffer);
      const xmlMatch = emlText.match(/<\?xml[\s\S]*<\/feedback>/i);
      if (xmlMatch) return xmlMatch[0];
      throw new Error('Could not extract XML from EML attachment.');
    }
    if (filename.endsWith('.msg')) return await parseMsgFile(arrayBuffer);

    const decoder = new TextDecoder('utf-8');
    const text = decoder.decode(arrayBuffer);
    if (text.includes('<feedback>') || text.includes('<?xml')) return text;
    throw new Error('Unsupported format or invalid XML.');
  }

  function renderDetailTable(records, orgName, domain, showBackNav = true) {
    if (showBackNav) {
      detailNav.classList.remove('hidden');
      detailTitle.textContent = `Details for: ${orgName} (${domain || 'Domain'})`;
    } else {
      detailNav.classList.add('hidden');
    }

    const aggregated = aggregateRecords(records);
    const sortedRecords = [...aggregated].sort((a, b) => compareIPs(a.sourceIp, b.sourceIp));

    tableHeaderRow.innerHTML = `
      <th>Source IP</th>
      <th>Count</th>
      <th>Header From</th>
      <th>Disposition</th>
      <th>DMARC</th>
      <th>SPF</th>
      <th>SPF Alignment</th>
      <th>DKIM</th>
      <th>DKIM Alignment</th>
    `;
    tableBody.innerHTML = '';

    sortedRecords.forEach(rec => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono"><strong>${rec.sourceIp}</strong></td>
        <td><strong>${rec.count}</strong></td>
        <td class="mono">${rec.headerFrom}</td>
        <td>${createBadge(rec.disposition)}</td>
        <td>${createBadge(rec.dmarcPassed)}</td>
        <td>${createBadge(rec.rawSpfResult)}</td>
        <td>${createBadge(rec.spfAligned)}</td>
        <td>${createBadge(rec.rawDkimResult)}</td>
        <td>${createBadge(rec.dkimAligned)}</td>
      `;
      tableBody.appendChild(tr);
    });
  }

  singleFileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    warningsWrapper.classList.add('hidden');

    try {
      fileInfo.textContent = `Processing file: ${file.name}...`;
      const rawXmlText = await extractXmlFromFile(file);

      output.textContent = rawXmlText;
      rawDetails.classList.remove('hidden');

      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(rawXmlText, 'application/xml');
      if (xmlDoc.getElementsByTagName('parsererror').length > 0) throw new Error('Invalid XML structure');

      const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
      const policy = xmlDoc.getElementsByTagName('policy_published')[0];
      const dateRange = meta ? meta.getElementsByTagName('date_range')[0] : null;

      const orgName = getText(meta, 'org_name');
      const domain = getText(policy, 'domain');
      const beginDate = formatUnixDate(getText(dateRange, 'begin'));
      const endDate = formatUnixDate(getText(dateRange, 'end'));

      const records = Array.from(xmlDoc.getElementsByTagName('record')).map(parseRecordNode);
      const totalMessages = records.reduce((sum, r) => sum + r.count, 0);

      renderDetailTable(records, orgName, domain, false);

      summarySection.innerHTML = `
        <div class="summary-item"><strong>Reporter</strong><span>${orgName}</span></div>
        <div class="summary-item"><strong>Domain</strong><span>${domain}</span></div>
        <div class="summary-item"><strong>Total Messages</strong><span>${totalMessages}</span></div>
        <div class="summary-item"><strong>Date Range</strong><span>${beginDate} – ${endDate}</span></div>
      `;
      summarySection.classList.remove('hidden');
      resultTable.classList.remove('hidden');
      fileInfo.textContent = `Showing report from: ${file.name}`;
    } catch (err) {
      fileInfo.textContent = `Error: ${err.message}`;
    } finally {
      singleFileInput.value = '';
    }
  });

  dirInput.addEventListener('change', async (event) => {
    const files = Array.from(event.target.files).filter(file => {
      const name = file.name.toLowerCase();
      return name.endsWith('.xml') || name.endsWith('.gz') || name.endsWith('.zip') || name.endsWith('.eml') || name.endsWith('.msg');
    });

    if (files.length === 0) {
      fileInfo.textContent = 'No valid DMARC report files found in the selected directory.';
      return;
    }

    rawDetails.classList.add('hidden');
    fileInfo.textContent = `Found ${files.length} files in directory. Processing...`;

    directoryCache = {};
    let totalGlobalMessages = 0;
    let successfulFiles = 0;
    let minTimestamp = Infinity;
    let maxTimestamp = -Infinity;
    const failedFiles = [];

    for (const file of files) {
      try {
        const rawXmlText = await extractXmlFromFile(file);
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(rawXmlText, 'application/xml');
        if (xmlDoc.getElementsByTagName('parsererror').length > 0) {
          throw new Error('XML Parser Error: Malformed XML');
        }

        const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
        const policy = xmlDoc.getElementsByTagName('policy_published')[0];
        const dateRange = meta ? meta.getElementsByTagName('date_range')[0] : null;

        const orgName = getText(meta, 'org_name', 'Unknown Reporter');
        const domain = getText(policy, 'domain', '');

        const beginTs = parseInt(getText(dateRange, 'begin', '0'), 10);
        const endTs = parseInt(getText(dateRange, 'end', '0'), 10);
        if (!isNaN(beginTs) && beginTs > 0 && beginTs < minTimestamp) minTimestamp = beginTs;
        if (!isNaN(endTs) && endTs > 0 && endTs > maxTimestamp) maxTimestamp = endTs;

        if (!directoryCache[orgName]) {
          directoryCache[orgName] = { orgName, domain, fileCount: 0, totalMessages: 0, passMessages: 0, records: [] };
        }
        directoryCache[orgName].fileCount++;

        const records = Array.from(xmlDoc.getElementsByTagName('record')).map(parseRecordNode);
        records.forEach(rec => {
          totalGlobalMessages += rec.count;
          directoryCache[orgName].totalMessages += rec.count;
          if (rec.dmarcPassed === 'pass') {
            directoryCache[orgName].passMessages += rec.count;
          }
          directoryCache[orgName].records.push(rec);
        });

        successfulFiles++;
      } catch (e) {
        failedFiles.push({ name: file.name, error: e.message });
      }
    }

    renderOverviewTable();

    const rangeStr = (minTimestamp !== Infinity && maxTimestamp !== -Infinity) 
      ? `${formatUnixDate(minTimestamp)} – ${formatUnixDate(maxTimestamp)}` 
      : 'Not available';

    summarySection.innerHTML = `
      <div class="summary-item"><strong>Loaded Files</strong><span>${successfulFiles} (${files.length} found)</span></div>
      <div class="summary-item"><strong>Total Messages</strong><span>${totalGlobalMessages}</span></div>
      <div class="summary-item"><strong>Unique Reporters</strong><span>${Object.keys(directoryCache).length}</span></div>
      <div class="summary-item"><strong>Date Range</strong><span>${rangeStr}</span></div>
    `;
    summarySection.classList.remove('hidden');

    if (failedFiles.length > 0) {
      warningsWrapper.className = 'warnings-container';
      warningsWrapper.innerHTML = `
        <details style="margin-top: 0;">
          <summary>⚠️ ${failedFiles.length} file(s) could not be parsed (Click for details)</summary>
          <div class="warnings-list">
            ${failedFiles.map(f => `<div><strong>${f.name}:</strong> ${f.error}</div>`).join('')}
          </div>
        </details>
      `;
      warningsWrapper.classList.remove('hidden');
    } else {
      warningsWrapper.classList.add('hidden');
    }

    resultTable.classList.remove('hidden');
    fileInfo.textContent = `Directory analysis complete: ${successfulFiles} files processed. (Click a reporter row to inspect details)`;
    dirInput.value = '';
  });

  function renderOverviewTable() {
    detailNav.classList.add('hidden');
    tableHeaderRow.innerHTML = `
      <th>Reporter (Org)</th>
      <th>Reports</th>
      <th>Total Messages</th>
      <th>Volume Share</th>
      <th>DMARC Pass %</th>
    `;
    tableBody.innerHTML = '';

    const totalGlobalMessages = Object.values(directoryCache).reduce((sum, d) => sum + d.totalMessages, 0);

    Object.keys(directoryCache).forEach(org => {
      const data = directoryCache[org];
      const share = totalGlobalMessages > 0 ? ((data.totalMessages / totalGlobalMessages) * 100).toFixed(1) : 0;
      const passPercent = data.totalMessages > 0 ? ((data.passMessages / data.totalMessages) * 100).toFixed(1) : 0;

      const passBadgeClass = passPercent >= 90 ? 'pass' : (passPercent >= 50 ? 'neutral' : 'fail');

      const tr = document.createElement('tr');
      tr.className = 'clickable-row';
      tr.innerHTML = `
        <td><strong>${org}</strong></td>
        <td>${data.fileCount}</td>
        <td><strong>${data.totalMessages}</strong></td>
        <td>${share}%</td>
        <td><span class="badge ${passBadgeClass}">${passPercent}%</span></td>
      `;

      tr.addEventListener('click', () => {
        renderDetailTable(data.records, data.orgName, data.domain, true);
      });

      tableBody.appendChild(tr);
    });
  }
});
