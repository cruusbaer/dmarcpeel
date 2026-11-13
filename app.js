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
    return new Date(ts * 1000).toLocaleString('sv-SE', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
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

  // --- Funktion för att aggregera rader med samma IP och identiskt utfall ---
  function aggregateRecords(records) {
    const map = new Map();

    records.forEach(rec => {
      // Skapa en unik nyckel baserat på IP samt alla statuskolumner
      const key = `${rec.sourceIp}|${rec.headerFrom}|${rec.disposition}|${rec.dmarcPassed}|${rec.rawSpfResult}|${rec.bestDkimResult}`;

      if (map.has(key)) {
        map.get(key).count += rec.count;
      } else {
        // Skapa en kopia av objektet så vi inte muterar originalet
        map.set(key, { ...rec });
      }
    });

    return Array.from(map.values());
  }

  async function parseMsgFile(arrayBuffer) {
    const uint8 = new Uint8Array(arrayBuffer);
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const fullText = decoder.decode(arrayBuffer);
    const xmlMatch = fullText.match(/<\?xml[\s\S]*<\/feedback>/i) || fullText.match(/<feedback[\s\S]*<\/feedback>/i);
    if (xmlMatch) return xmlMatch[0];

    for (let i = 0; i < uint8.length - 4; i++) {
      if (uint8[i] === 0x1f && uint8[i+1] === 0x8b) {
        try { return pako.inflate(uint8.slice(i), { to: 'string' }); } catch (e) {}
      }
      if (uint8[i] === 0x50 && uint8[i+1] === 0x4b && uint8[i+2] === 0x03 && uint8[i+3] === 0x04) {
        try {
          const zip = new JSZip();
          const zipContent = await zip.loadAsync(uint8.slice(i));
          const xmlFilename = Object.keys(zipContent.files).find(name => name.toLowerCase().endsWith('.xml'));
          if (xmlFilename) return await zipContent.files[xmlFilename].async('string');
        } catch (e) {}
      }
    }
    throw new Error('Kunde inte extrahera DMARC-bilaga ur .msg.');
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
      if (!xmlFilename) throw new Error('Ingen XML-fil i ZIP.');
      return await zipContent.files[xmlFilename].async('string');
    }
    if (filename.endsWith('.eml')) {
      const emlText = new TextDecoder().decode(arrayBuffer);
      const xmlMatch = emlText.match(/<\?xml[\s\S]*<\/feedback>/i);
      if (xmlMatch) return xmlMatch[0];
      throw new Error('Kunde inte läsa EML-bilaga.');
    }
    if (filename.endsWith('.msg')) return await parseMsgFile(arrayBuffer);

    const decoder = new TextDecoder('utf-8');
    const text = decoder.decode(arrayBuffer);
    if (text.includes('<feedback>') || text.includes('<?xml')) return text;
    throw new Error('Ogiltigt format eller ej XML.');
  }

  function renderDetailTable(records, orgName, domain) {
    detailNav.classList.remove('hidden');
    detailTitle.textContent = `Detaljer för: ${orgName} (${domain || 'Domän'})`;

    // 1. Aggregera rader med identiskt utfall och IP
    const aggregated = aggregateRecords(records);

    // 2. Sortera numeriskt på IP
    const sortedRecords = [...aggregated].sort((a, b) => compareIPs(a.sourceIp, b.sourceIp));

    tableHeaderRow.innerHTML = `
      <th>Sändande IP</th>
      <th>Antal</th>
      <th>Header From</th>
      <th>Åtgärd</th>
      <th>DMARC</th>
      <th>SPF</th>
      <th>DKIM</th>
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
        <td>${createBadge(rec.bestDkimResult)}</td>
      `;
      tableBody.appendChild(tr);
    });
  }

  // --- 1. Hantera enskild fil ---
  singleFileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    warningsWrapper.classList.add('hidden');

    try {
      fileInfo.textContent = `Bearbetar fil: ${file.name}...`;
      const rawXmlText = await extractXmlFromFile(file);

      // Visa rå-XML för enskild fil
      output.textContent = rawXmlText;
      rawDetails.classList.remove('hidden');

      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(rawXmlText, 'application/xml');
      if (xmlDoc.getElementsByTagName('parsererror').length > 0) throw new Error('Ogiltig XML-struktur');

      const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
      const policy = xmlDoc.getElementsByTagName('policy_published')[0];
      const dateRange = meta ? meta.getElementsByTagName('date_range')[0] : null;

      const orgName = getText(meta, 'org_name');
      const domain = getText(policy, 'domain');
      const beginDate = formatUnixDate(getText(dateRange, 'begin'));
      const endDate = formatUnixDate(getText(dateRange, 'end'));

      const records = Array.from(xmlDoc.getElementsByTagName('record')).map(record => {
        const row = record.getElementsByTagName('row')[0];
        const identifiers = record.getElementsByTagName('identifiers')[0];
        const authResults = record.getElementsByTagName('auth_results')[0];
        const policyEval = row ? row.getElementsByTagName('policy_evaluated')[0] : null;

        const sourceIp = getText(row, 'source_ip');
        const count = parseInt(getText(row, 'count', '0'), 10);
        const disposition = getText(policyEval, 'disposition', 'none');
        const evalDkim = getText(policyEval, 'dkim');
        const evalSpf = getText(policyEval, 'spf');
        const dmarcPassed = (evalDkim === 'pass' || evalSpf === 'pass') ? 'pass' : 'fail';
        const headerFrom = getText(identifiers, 'header_from');

        const spfNode = authResults ? authResults.getElementsByTagName('spf')[0] : null;
        const rawSpfResult = getText(spfNode, 'result', 'none');

        const dkimNodes = authResults ? Array.from(authResults.getElementsByTagName('dkim')) : [];
        const bestDkimResult = dkimNodes.length > 0 ? getText(dkimNodes[0], 'result', 'none') : 'none';

        return { sourceIp, count, disposition, dmarcPassed, headerFrom, rawSpfResult, bestDkimResult };
      });

      const totalMessages = records.reduce((sum, r) => sum + r.count, 0);

      detailNav.classList.add('hidden');
      renderDetailTable(records, orgName, domain);

      summarySection.innerHTML = `
        <div class="summary-item"><strong>Rapportör</strong><span>${orgName}</span></div>
        <div class="summary-item"><strong>Domän</strong><span>${domain}</span></div>
        <div class="summary-item"><strong>Totalt antal mail</strong><span>${totalMessages} st</span></div>
        <div class="summary-item"><strong>Tidsintervall</strong><span>${beginDate} – ${endDate}</span></div>
      `;
      summarySection.classList.remove('hidden');
      resultTable.classList.remove('hidden');
      fileInfo.textContent = `Visar rapport från: ${file.name}`;
    } catch (err) {
      fileInfo.textContent = `Fel: ${err.message}`;
    } finally {
      singleFileInput.value = '';
    }
  });

  // --- 2. Hantera hel katalog ---
  dirInput.addEventListener('change', async (event) => {
    const files = Array.from(event.target.files).filter(file => {
      const name = file.name.toLowerCase();
      return name.endsWith('.xml') || name.endsWith('.gz') || name.endsWith('.zip') || name.endsWith('.eml') || name.endsWith('.msg');
    });

    if (files.length === 0) {
      fileInfo.textContent = 'Inga giltiga DMARC-filer hittades i katalogen.';
      return;
    }

    // Dölj rå-XML vid kataloginläsning
    rawDetails.classList.add('hidden');

    fileInfo.textContent = `Hittade ${files.length} filer i katalogen. Bearbetar...`;

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
          throw new Error('Parsererror: Ej giltig XML');
        }

        const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
        const policy = xmlDoc.getElementsByTagName('policy_published')[0];
        const dateRange = meta ? meta.getElementsByTagName('date_range')[0] : null;

        const orgName = getText(meta, 'org_name', 'Okänd rapportör');
        const domain = getText(policy, 'domain', '');

        const beginTs = parseInt(getText(dateRange, 'begin', '0'), 10);
        const endTs = parseInt(getText(dateRange, 'end', '0'), 10);
        if (!isNaN(beginTs) && beginTs > 0 && beginTs < minTimestamp) minTimestamp = beginTs;
        if (!isNaN(endTs) && endTs > 0 && endTs > maxTimestamp) maxTimestamp = endTs;

        if (!directoryCache[orgName]) {
          directoryCache[orgName] = { orgName, domain, fileCount: 0, totalMessages: 0, passMessages: 0, records: [] };
        }
        directoryCache[orgName].fileCount++;

        const records = Array.from(xmlDoc.getElementsByTagName('record'));
        records.forEach(record => {
          const row = record.getElementsByTagName('row')[0];
          const identifiers = record.getElementsByTagName('identifiers')[0];
          const authResults = record.getElementsByTagName('auth_results')[0];
          const policyEval = row ? row.getElementsByTagName('policy_evaluated')[0] : null;

          const sourceIp = getText(row, 'source_ip');
          const count = parseInt(getText(row, 'count', '0'), 10);
          const disposition = getText(policyEval, 'disposition', 'none');
          const evalDkim = getText(policyEval, 'dkim');
          const evalSpf = getText(policyEval, 'spf');
          const dmarcPassed = (evalDkim === 'pass' || evalSpf === 'pass') ? 'pass' : 'fail';
          const headerFrom = getText(identifiers, 'header_from');

          const spfNode = authResults ? authResults.getElementsByTagName('spf')[0] : null;
          const rawSpfResult = getText(spfNode, 'result', 'none');
          const dkimNodes = authResults ? Array.from(authResults.getElementsByTagName('dkim')) : [];
          const bestDkimResult = dkimNodes.length > 0 ? getText(dkimNodes[0], 'result', 'none') : 'none';

          totalGlobalMessages += count;
          directoryCache[orgName].totalMessages += count;
          if (dmarcPassed === 'pass') {
            directoryCache[orgName].passMessages += count;
          }

          directoryCache[orgName].records.push({ sourceIp, count, disposition, dmarcPassed, headerFrom, rawSpfResult, bestDkimResult });
        });

        successfulFiles++;
      } catch (e) {
        failedFiles.push({ name: file.name, error: e.message });
      }
    }

    renderOverviewTable();

    const rangeStr = (minTimestamp !== Infinity && maxTimestamp !== -Infinity) 
      ? `${formatUnixDate(minTimestamp)} – ${formatUnixDate(maxTimestamp)}` 
      : 'Ej tillgängligt';

    summarySection.innerHTML = `
      <div class="summary-item"><strong>Inlästa filer</strong><span>${successfulFiles} st (${files.length} hittades)</span></div>
      <div class="summary-item"><strong>Totalt antal mail</strong><span>${totalGlobalMessages} st</span></div>
      <div class="summary-item"><strong>Unika rapportörer</strong><span>${Object.keys(directoryCache).length} st</span></div>
      <div class="summary-item"><strong>Tidsintervall</strong><span>${rangeStr}</span></div>
    `;
    summarySection.classList.remove('hidden');

    if (failedFiles.length > 0) {
      warningsWrapper.innerHTML = `
        <details>
          <summary>⚠️ ${failedFiles.length} filer kunde inte läsas in (Klicka för detaljer)</summary>
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
    fileInfo.textContent = `Kataloganalys klar: ${successfulFiles} filer bearbetade. (Klicka på en rapportör för detaljer)`;
    dirInput.value = '';
  });

  function renderOverviewTable() {
    detailNav.classList.add('hidden');
    tableHeaderRow.innerHTML = `
      <th>Rapportör (Org)</th>
      <th>Antal rapporter</th>
      <th>Totalt antal mail</th>
      <th>Andel av volym</th>
      <th>DMARC Pass %</th>
    `;
    tableBody.innerHTML = '';

    Object.keys(directoryCache).forEach(org => {
      const data = directoryCache[org];
      const totalGlobalMessages = Object.values(directoryCache).reduce((sum, d) => sum + d.totalMessages, 0);
      const share = totalGlobalMessages > 0 ? ((data.totalMessages / totalGlobalMessages) * 100).toFixed(1) : 0;
      const passPercent = data.totalMessages > 0 ? ((data.passMessages / data.totalMessages) * 100).toFixed(1) : 0;

      const passBadgeClass = passPercent >= 90 ? 'pass' : (passPercent >= 50 ? 'neutral' : 'fail');

      const tr = document.createElement('tr');
      tr.className = 'clickable-row';
      tr.innerHTML = `
        <td><strong>${org}</strong></td>
        <td>${data.fileCount} st</td>
        <td><strong>${data.totalMessages}</strong></td>
        <td>${share}%</td>
        <td><span class="badge ${passBadgeClass}">${passPercent}%</span></td>
      `;

      tr.addEventListener('click', () => {
        renderDetailTable(data.records, data.orgName, data.domain);
      });

      tableBody.appendChild(tr);
    });
  }
});
