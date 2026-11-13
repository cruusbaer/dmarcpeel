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

  openFileBtn.addEventListener('click', () => singleFileInput.click());
  openDirBtn.addEventListener('click', () => dirInput.click());

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

  // --- Robust intern MSG/OLE- och strömpares---
  async function parseMsgFile(arrayBuffer) {
    const uint8 = new Uint8Array(arrayBuffer);
    
    // 1. Kolla om rapporten ligger som ren text/XML inbäddad
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const fullText = decoder.decode(arrayBuffer);
    const xmlMatch = fullText.match(/<\?xml[\s\S]*<\/feedback>/i) || fullText.match(/<feedback[\s\S]*<\/feedback>/i);
    if (xmlMatch) return xmlMatch[0];

    // 2. Skanna igenom binärdatan efter GZ (1f 8b) eller ZIP (50 4b 03 04) signaturer
    for (let i = 0; i < uint8.length - 4; i++) {
      // GZ signatur
      if (uint8[i] === 0x1f && uint8[i+1] === 0x8b) {
        const sliced = uint8.slice(i);
        try {
          return pako.inflate(sliced, { to: 'string' });
        } catch (e) {
          // Fortsätt leta
        }
      }
      // ZIP signatur (PK)
      if (uint8[i] === 0x50 && uint8[i+1] === 0x4b && uint8[i+2] === 0x03 && uint8[i+3] === 0x04) {
        const sliced = uint8.slice(i);
        try {
          const zip = new JSZip();
          const zipContent = await zip.loadAsync(sliced);
          const xmlFilename = Object.keys(zipContent.files).find(name => name.toLowerCase().endsWith('.xml'));
          if (xmlFilename) {
            return await zipContent.files[xmlFilename].async('string');
          }
        } catch (e) {
          // Fortsätt leta
        }
      }
    }

    throw new Error('Kunde inte extrahera DMARC-bilaga ur Outlook .msg-filen.');
  }

  // --- Intern uppackningsmotor ---
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

    if (filename.endsWith('.msg')) {
      return await parseMsgFile(arrayBuffer);
    }

    const decoder = new TextDecoder('utf-8');
    const text = decoder.decode(arrayBuffer);
    if (text.includes('<feedback>') || text.includes('<?xml')) return text;

    throw new Error('Ogiltigt format.');
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

      const records = Array.from(xmlDoc.getElementsByTagName('record'));
      let totalMessages = 0;

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

      records.forEach(record => {
        const row = record.getElementsByTagName('row')[0];
        const identifiers = record.getElementsByTagName('identifiers')[0];
        const authResults = record.getElementsByTagName('auth_results')[0];
        const policyEval = row ? row.getElementsByTagName('policy_evaluated')[0] : null;

        const sourceIp = getText(row, 'source_ip');
        const count = parseInt(getText(row, 'count', '0'), 10);
        totalMessages += count;

        const disposition = getText(policyEval, 'disposition', 'none');
        const evalDkim = getText(policyEval, 'dkim');
        const evalSpf = getText(policyEval, 'spf');
        const dmarcPassed = (evalDkim === 'pass' || evalSpf === 'pass') ? 'pass' : 'fail';
        const headerFrom = getText(identifiers, 'header_from');

        const spfNode = authResults ? authResults.getElementsByTagName('spf')[0] : null;
        const rawSpfResult = getText(spfNode, 'result', 'none');

        const dkimNodes = authResults ? Array.from(authResults.getElementsByTagName('dkim')) : [];
        const bestDkimResult = dkimNodes.length > 0 ? getText(dkimNodes[0], 'result', 'none') : 'none';

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="mono"><strong>${sourceIp}</strong></td>
          <td><strong>${count}</strong></td>
          <td class="mono">${headerFrom}</td>
          <td>${createBadge(disposition)}</td>
          <td>${createBadge(dmarcPassed)}</td>
          <td>${createBadge(rawSpfResult)}</td>
          <td>${createBadge(bestDkimResult)}</td>
        `;
        tableBody.appendChild(tr);
      });

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

  // --- 2. Hantera hel katalog (Aggregerad vy) ---
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

    const aggregator = {};
    let totalGlobalMessages = 0;
    let successfulFiles = 0;

    for (const file of files) {
      try {
        const rawXmlText = await extractXmlFromFile(file);
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(rawXmlText, 'application/xml');
        if (xmlDoc.getElementsByTagName('parsererror').length > 0) continue;

        const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
        const orgName = getText(meta, 'org_name', 'Okänd rapportör');

        if (!aggregator[orgName]) {
          aggregator[orgName] = { fileCount: 0, totalMessages: 0 };
        }
        aggregator[orgName].fileCount++;

        const records = Array.from(xmlDoc.getElementsByTagName('record'));
        records.forEach(record => {
          const row = record.getElementsByTagName('row')[0];
          const count = parseInt(getText(row, 'count', '0'), 10);
          totalGlobalMessages += count;
          aggregator[orgName].totalMessages += count;
        });

        successfulFiles++;
      } catch (e) {
        // Hoppa över filer som inte kunde packas upp
      }
    }

    tableHeaderRow.innerHTML = `
      <th>Rapportör (Org)</th>
      <th>Antal rapporter</th>
      <th>Totalt antal mail</th>
      <th>Andel av volym</th>
    `;
    tableBody.innerHTML = '';

    Object.keys(aggregator).forEach(org => {
      const data = aggregator[org];
      const share = totalGlobalMessages > 0 ? ((data.totalMessages / totalGlobalMessages) * 100).toFixed(1) : 0;

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${org}</strong></td>
        <td>${data.fileCount} st</td>
        <td><strong>${data.totalMessages}</strong></td>
        <td>${share}%</td>
      `;
      tableBody.appendChild(tr);
    });

    summarySection.innerHTML = `
      <div class="summary-item"><strong>Inlästa filer</strong><span>${successfulFiles} st (${files.length} hittades)</span></div>
      <div class="summary-item"><strong>Totalt antal mail</strong><span>${totalGlobalMessages} st</span></div>
      <div class="summary-item"><strong>Unika rapportörer</strong><span>${Object.keys(aggregator).length} st</span></div>
    `;

    summarySection.classList.remove('hidden');
    resultTable.classList.remove('hidden');
    fileInfo.textContent = `Kataloganalys klar: ${successfulFiles} filer bearbetade.`;
    dirInput.value = '';
  });
});
