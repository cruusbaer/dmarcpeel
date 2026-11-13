document.addEventListener('DOMContentLoaded', () => {
  const openFileBtn = document.getElementById('openFileBtn');
  const singleFileInput = document.getElementById('singleFileInput');
  const openDirBtn = document.getElementById('openDirBtn');
  const dirInput = document.getElementById('dirInput');
  const fileInfo = document.getElementById('fileInfo');
  const summarySection = document.getElementById('summarySection');
  const resultTable = document.getElementById('resultTable');
  const tableHeaderRow = document.getElementById('tableHeaderRow');
  const tableBody = document.getElementById('tableBody');
  const detailNav = document.getElementById('detailNav');
  const backToOverviewBtn = document.getElementById('backToOverviewBtn');
  const detailTitle = document.getElementById('detailTitle');

  let directoryCache = {}; // Sparar undan all data per rapportör i minnet

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
    throw new Error('Kunde inte extrahera DMARC-bilaga.');
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
    throw new Error('Ogiltigt format.');
  }

  // --- Hjälpfunktion för att rita detaljtabell (används både för enskild fil och klick på katalog) ---
  function renderDetailTable(records, orgName, domain) {
    detailNav.classList.remove('hidden');
    detailTitle.textContent = `Detaljer för: ${orgName} (${domain || 'Domän'})`;

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

    records.forEach(rec => {
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

    try {
      fileInfo.textContent = `Bearbetar fil: ${file.name}...`;
      const rawXmlText = await extractXmlFromFile(file);

      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(rawXmlText, 'application/xml');
      if (xmlDoc.getElementsByTagName('parsererror').length > 0) throw new Error('Ogiltig XML');

      const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
      const policy = xmlDoc.getElementsByTagName('policy_published')[0];
      const orgName = getText(meta, 'org_name');
      const domain = getText(policy, 'domain');

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

  // --- 2. Hantera hel katalog (Aggregerad vy med cache) ---
  dirInput.addEventListener('change', async (event) => {
    const files = Array.from(event.target.files).filter(file => {
      const name = file.name.toLowerCase();
      return name.endsWith('.xml') || name.endsWith('.gz') || name.endsWith('.zip') || name.endsWith('.eml') || name.endsWith('.msg');
    });

    if (files.length === 0) {
      fileInfo.textContent = 'Inga giltiga DMARC-filer hittades i katalogen.';
      return;
    }

    fileInfo.textContent = `Hittade ${files.length} rapporter i katalogen. Sammanställer...`;

    directoryCache = {};
    let totalGlobalMessages = 0;
    let successfulFiles = 0;

    for (const file of files) {
      try {
        const rawXmlText = await extractXmlFromFile(file);
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(rawXmlText, 'application/xml');
        if (xmlDoc.getElementsByTagName('parsererror').length > 0) continue;

        const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
        const policy = xmlDoc.getElementsByTagName('policy_published')[0];
        const orgName = getText(meta, 'org_name', 'Okänd rapportör');
        const domain = getText(policy, 'domain', '');

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
      } catch (e) {}
    }

    renderOverviewTable();

    summarySection.innerHTML = `
      <div class="summary-item"><strong>Inlästa filer</strong><span>${successfulFiles} st (${files.length} hittades)</span></div>
      <div class="summary-item"><strong>Totalt antal mail</strong><span>${totalGlobalMessages} st</span></div>
      <div class="summary-item"><strong>Unika rapportörer</strong><span>${Object.keys(directoryCache).length} st</span></div>
    `;
    summarySection.classList.remove('hidden');
    resultTable.classList.remove('hidden');
    fileInfo.textContent = `Kataloganalys klar: ${successfulFiles} filer bearbetade. (Klicka på en rad för detaljer)`;
    dirInput.value = '';
  });

  // --- Rita översiktstabellen ---
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

      // Klickhändelse för att borra ner i detaljer för vald rapportör
      tr.addEventListener('click', () => {
        renderDetailTable(data.records, data.orgName, data.domain);
      });

      tableBody.appendChild(tr);
    });
  }
});
