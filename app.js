document.addEventListener('DOMContentLoaded', () => {
  const openFileBtn = document.getElementById('openFileBtn');
  const fileInput = document.getElementById('fileInput');
  const fileInfo = document.getElementById('fileInfo');
  const metaSection = document.getElementById('metaSection');
  const resultTable = document.getElementById('resultTable');
  const tableBody = document.getElementById('tableBody');
  const rawDetails = document.getElementById('rawDetails');
  const output = document.getElementById('output');

  openFileBtn.addEventListener('click', () => {
    fileInput.click();
  });

  function getText(parent, tagName, fallback = '–') {
    if (!parent) return fallback;
    const el = parent.getElementsByTagName(tagName)[0];
    return el && el.textContent ? el.textContent.trim() : fallback;
  }

  function createBadge(value) {
    if (!value) value = 'none';
    const val = value.toLowerCase();
    let cls = 'neutral';
    
    if (val === 'pass') {
      cls = 'pass';
    } else if (val === 'fail' || val === 'reject' || val === 'quarantine') {
      cls = 'fail';
    } else {
      cls = 'neutral';
    }

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

  // --- Egen intern minimalistisk OLE/MSG-parser ---
  async function parseMsgFile(arrayBuffer) {
    const uint8 = new Uint8Array(arrayBuffer);
    
    // 1. Kolla om rapporten ligger som ren text/XML inbäddad i MSG-strukturen
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const fullText = decoder.decode(arrayBuffer);
    const xmlMatch = fullText.match(/<\?xml[\s\S]*<\/feedback>/i);
    if (xmlMatch) return xmlMatch[0];

    // 2. Leta efter binära signaturer för GZ (1f 8b) eller ZIP (50 4b) inuti .msg-binärpannan
    for (let i = 0; i < uint8.length - 4; i++) {
      if (uint8[i] === 0x1f && uint8[i+1] === 0x8b) {
        const sliced = uint8.slice(i);
        try {
          return pako.inflate(sliced, { to: 'string' });
        } catch (e) {
          // Ignorera och fortsätt
        }
      }
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
          // Ignorera och fortsätt
        }
      }
    }

    throw new Error('Kunde inte extrahera bilaga automatiskt ur Outlook .msg-filen.');
  }

  // --- Huvudrouter för filformat ---
  async function extractXmlFromFile(file) {
    const filename = file.name.toLowerCase();
    const arrayBuffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);

    // GZ
    if (filename.endsWith('.gz') || (uint8Array.length > 2 && uint8Array[0] === 0x1f && uint8Array[1] === 0x8b)) {
      return pako.inflate(uint8Array, { to: 'string' });
    }
    
    // ZIP
    if (filename.endsWith('.zip') || (uint8Array.length > 2 && uint8Array[0] === 0x50 && uint8Array[1] === 0x4b)) {
      const zip = new JSZip();
      const zipContent = await zip.loadAsync(arrayBuffer);
      const xmlFilename = Object.keys(zipContent.files).find(name => name.toLowerCase().endsWith('.xml'));
      if (!xmlFilename) throw new Error('Ingen XML-fil hittades i ZIP-arkivet.');
      return await zipContent.files[xmlFilename].async('string');
    }

    // EML
    if (filename.endsWith('.eml')) {
      const emlText = new TextDecoder().decode(arrayBuffer);
      const xmlMatch = emlText.match(/<\?xml[\s\S]*<\/feedback>/i);
      if (xmlMatch) return xmlMatch[0];
      throw new Error('EML-filen kunde inte läsas.');
    }

    // MSG
    if (filename.endsWith('.msg')) {
      return await parseMsgFile(arrayBuffer);
    }

    // Standard XML
    const decoder = new TextDecoder('utf-8');
    const text = decoder.decode(arrayBuffer);
    if (text.includes('<feedback>') || text.includes('<?xml')) {
      return text;
    }

    throw new Error('Filen verkar inte vara en giltig DMARC-rapport.');
  }

  fileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      fileInfo.textContent = `Bearbetar fil: ${file.name}...`;

      const rawXmlText = await extractXmlFromFile(file);

      fileInfo.textContent = `Vald fil: ${file.name} (${file.size} bytes)`;
      output.textContent = rawXmlText;

      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(rawXmlText, 'application/xml');

      if (xmlDoc.getElementsByTagName('parsererror').length > 0) {
        throw new Error('Det uppackade innehållet är inte en giltig DMARC XML-rapport.');
      }

      const meta = xmlDoc.getElementsByTagName('report_metadata')[0];
      const policy = xmlDoc.getElementsByTagName('policy_published')[0];
      const dateRange = meta ? meta.getElementsByTagName('date_range')[0] : null;

      const orgName = getText(meta, 'org_name');
      const domain = getText(policy, 'domain');
      const pPolicy = getText(policy, 'p');
      const beginDate = formatUnixDate(getText(dateRange, 'begin'));
      const endDate = formatUnixDate(getText(dateRange, 'end'));

      const records = Array.from(xmlDoc.getElementsByTagName('record'));
      let totalMessages = 0;

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
        const rawSpfDomain = getText(spfNode, 'domain', '');

        const dkimNodes = authResults ? Array.from(authResults.getElementsByTagName('dkim')) : [];
        let dkimDetailsHtml = '';
        let bestDkimResult = 'none';

        if (dkimNodes.length > 0) {
          bestDkimResult = getText(dkimNodes[0], 'result', 'none');
          dkimDetailsHtml = dkimNodes.map(d => {
            const res = getText(d, 'result');
            const dom = getText(d, 'domain', '');
            const sel = getText(d, 'selector', '');
            return `${res} (${dom}${sel ? ' / ' + sel : ''})`;
          }).join('<br>');
        } else {
          dkimDetailsHtml = 'Ingen signatur (none)';
        }

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="mono"><strong>${sourceIp}</strong></td>
          <td><strong>${count}</strong></td>
          <td class="mono">${headerFrom}</td>
          <td>${createBadge(disposition)}</td>
          <td>${createBadge(dmarcPassed)}</td>
          <td>
            ${createBadge(rawSpfResult)}
            <span class="sub-detail">${rawSpfDomain}</span>
          </td>
          <td>
            ${createBadge(bestDkimResult)}
            <span class="sub-detail">${dkimDetailsHtml}</span>
          </td>
        `;
        tableBody.appendChild(tr);
      });

      metaSection.innerHTML = `
        <div class="meta-item"><strong>Rapportör</strong><span>${orgName}</span></div>
        <div class="meta-item"><strong>Din domän (Policy)</strong><span>${domain} (p=${pPolicy})</span></div>
        <div class="meta-item"><strong>Totalt antal mail</strong><span>${totalMessages} st (${records.length} poster)</span></div>
        <div class="meta-item"><strong>Period</strong><span>${beginDate} – ${endDate}</span></div>
      `;

      metaSection.classList.remove('hidden');
      resultTable.classList.remove('hidden');
      rawDetails.classList.remove('hidden');

    } catch (err) {
      if (err.name !== 'AbortError') {
        console.error(err);
        fileInfo.textContent = `Fel vid bearbetning: ${err.message}`;
      }
    } finally {
      fileInput.value = '';
    }
  });
});
