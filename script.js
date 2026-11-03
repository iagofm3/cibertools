// ==========================================================
// 1. UTILIDADES IPv4 & CALCULADORA DE SUBREDES + VLSM
// ==========================================================
function ipToInt(ip) {
  const parts = ip.trim().split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join('.');
}

function intToBinaryDots(int) {
  return [
    ((int >>> 24) & 255).toString(2).padStart(8, '0'),
    ((int >>> 16) & 255).toString(2).padStart(8, '0'),
    ((int >>> 8) & 255).toString(2).padStart(8, '0'),
    (int & 255).toString(2).padStart(8, '0')
  ].join('.');
}

function updateSubnetCalc() {
  const ipStr = document.getElementById('ipInput').value;
  const cidr = parseInt(document.getElementById('cidrInput').value, 10);
  const ipInt = ipToInt(ipStr);
  if (ipInt === null) return;

  const maskInt = cidr === 0 ? 0 : (0xffffffff << (32 - cidr)) >>> 0;
  const wildcardInt = (~maskInt) >>> 0;
  const netInt = (ipInt & maskInt) >>> 0;
  const bcastInt = (netInt | wildcardInt) >>> 0;
  const firstHost = cidr >= 31 ? netInt : (netInt + 1) >>> 0;
  const lastHost = cidr >= 31 ? bcastInt : (bcastInt - 1) >>> 0;
  const usableHosts = cidr >= 31 ? 0 : Math.pow(2, 32 - cidr) - 2;

  document.getElementById('resNetAddr').textContent = `${intToIp(netInt)}/${cidr}`;
  document.getElementById('resNetMask').textContent = intToIp(maskInt);
  document.getElementById('resWildcard').textContent = intToIp(wildcardInt);
  document.getElementById('resBroadcast').textContent = intToIp(bcastInt);
  document.getElementById('resRange').textContent = `${intToIp(firstHost)} – ${intToIp(lastHost)}`;
  document.getElementById('resHosts').textContent = `${usableHosts.toLocaleString('es-ES')} equipos`;
  document.getElementById('resBinary').textContent = intToBinaryDots(maskInt);
}

function calculateVlsmTable() {
  const baseIpStr = document.getElementById('vlsmBaseIp').value;
  const hostsRaw = document.getElementById('vlsmHosts').value;
  const baseInt = ipToInt(baseIpStr);
  const tbody = document.getElementById('vlsmTableBody');
  if (baseInt === null || !tbody) return;

  const requested = hostsRaw
    .split(',')
    .map((x) => parseInt(x.trim(), 10))
    .filter((n) => !isNaN(n) && n > 0)
    .sort((a, b) => b - a);

  tbody.innerHTML = '';
  let currentNet = baseInt;

  requested.forEach((reqHosts, idx) => {
    // Buscar bits de host necesarios: 2^h - 2 >= reqHosts
    let hostBits = 2;
    while (Math.pow(2, hostBits) - 2 < reqHosts && hostBits < 30) {
      hostBits++;
    }
    const cidr = 32 - hostBits;
    const blockSize = Math.pow(2, hostBits);
    const usable = blockSize - 2;
    const maskInt = (0xffffffff << hostBits) >>> 0;
    const netAddr = currentNet;
    const bcastAddr = (netAddr + blockSize - 1) >>> 0;
    const firstH = (netAddr + 1) >>> 0;
    const lastH = (bcastAddr - 1) >>> 0;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>VLAN #${idx + 1}</strong></td>
      <td>${reqHosts}</td>
      <td style="color:#34d399">${usable}</td>
      <td><strong>${intToIp(netAddr)}/${cidr}</strong></td>
      <td>${intToIp(maskInt)}</td>
      <td>${intToIp(firstH)} – ${intToIp(lastH)}</td>
      <td>${intToIp(bcastAddr)}</td>
    `;
    tbody.appendChild(tr);

    currentNet = (bcastAddr + 1) >>> 0;
  });
}

// ==========================================================
// 2. GENERADOR SPF & DMARC
// ==========================================================
function updateDmarcGenerator() {
  const domain = (document.getElementById('dmarcDomain').value || 'miempresa.es').trim();
  const provider = document.getElementById('spfProvider').value;
  const policy = document.getElementById('dmarcPolicy').value;
  const email = (document.getElementById('dmarcEmail').value || `seguridad@${domain}`).trim();

  document.getElementById('spfOutput').textContent = `v=spf1 ${provider} ~all`;
  document.getElementById('dmarcOutput').textContent = `v=DMARC1; p=${policy}; rua=mailto:${email}; pct=100; adkim=r; aspf=r;`;
}

// ==========================================================
// 3. CONSTRUCTOR DE COMANDOS NMAP & BUSCADOR DE PUERTOS
// ==========================================================
const criticalPorts = [
  { port: 21, proto: 'TCP', service: 'FTP', note: 'Tráfico en texto plano. Auditar acceso anónimo (ftp-anon).' },
  { port: 22, proto: 'TCP', service: 'SSH', note: 'Administración remota. Desactivar root login y usar clave pública.' },
  { port: 23, proto: 'TCP', service: 'Telnet', note: 'CRÍTICO: Credenciales sin cifrar. Sustituir siempre por SSH.' },
  { port: 25, proto: 'TCP', service: 'SMTP', note: 'Servidor de correo. Verificar Open Relay y registros SPF/DMARC.' },
  { port: 53, proto: 'TCP/UDP', service: 'DNS', note: 'Comprobar transferencia de zona (AXFR) y recursión abierta.' },
  { port: 80, proto: 'TCP', service: 'HTTP', note: 'Web sin cifrar. Forzar redirección 301 a HTTPS (443).' },
  { port: 139, proto: 'TCP', service: 'NetBIOS', note: 'Enumeración de recursos compartidos en redes Windows.' },
  { port: 443, proto: 'TCP', service: 'HTTPS', note: 'Revisar certificado TLS y cabeceras de seguridad OWASP.' },
  { port: 445, proto: 'TCP', service: 'SMB', note: 'CRÍTICO: Objetivo frecuente de ransomware (EternalBlue / SMB Signing).' },
  { port: 1433, proto: 'TCP', service: 'MS-SQL', note: 'Base de datos Microsoft SQL Server. No exponer a Internet.' },
  { port: 3306, proto: 'TCP', service: 'MySQL / MariaDB', note: 'Base de datos. Restringir acceso a localhost (127.0.0.1).' },
  { port: 3389, proto: 'TCP', service: 'RDP (Escritorio Remoto)', note: 'ALTO RIESGO: Objetivo #1 de fuerza bruta. Proteger tras VPN + MFA.' },
  { port: 5432, proto: 'TCP', service: 'PostgreSQL', note: 'Base de datos relacional. Revisar pg_hba.conf.' },
  { port: 8080, proto: 'TCP', service: 'HTTP-Alt / Proxy', note: 'Paneles de administración (Tomcat, Jenkins) frecuentemente expuestos.' }
];

function updateNmapBuilder() {
  const target = (document.getElementById('nmapTarget').value || '192.168.1.0/24').trim();
  const scanType = document.getElementById('nmapScanType').value;
  const speed = document.getElementById('nmapSpeed').value;
  const flags = [scanType, speed];

  if (document.getElementById('nmapSv').checked && scanType !== '-sn') flags.push('-sV');
  if (document.getElementById('nmapOs').checked && scanType !== '-sn') flags.push('-O');
  if (document.getElementById('nmapSc').checked && scanType !== '-sn') flags.push('-sC');
  if (document.getElementById('nmapVuln').checked && scanType !== '-sn') flags.push('--script vuln');
  if (document.getElementById('nmapAllPorts').checked && scanType !== '-sn') flags.push('-p-');
  if (document.getElementById('nmapPn').checked) flags.push('-Pn');

  document.getElementById('nmapOutput').textContent = `sudo nmap ${flags.join(' ')} ${target}`;
}

function renderPortsTable(filter = '') {
  const tbody = document.getElementById('portsTableBody');
  if (!tbody) return;
  const q = filter.trim().toLowerCase();
  tbody.innerHTML = '';

  criticalPorts
    .filter(
      (p) =>
        !q ||
        String(p.port).includes(q) ||
        p.service.toLowerCase().includes(q) ||
        p.note.toLowerCase().includes(q)
    )
    .forEach((p) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong style="color:#38bdf8">${p.port}</strong></td>
        <td>${p.proto}</td>
        <td><strong>${p.service}</strong></td>
        <td>${p.note}</td>
      `;
      tbody.appendChild(tr);
    });
}

// ==========================================================
// 4. ENTROPÍA DE CONTRASEÑAS & HASHES SHA-256
// ==========================================================
function generateStrongPassword() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}';
  const arr = new Uint32Array(20);
  window.crypto.getRandomValues(arr);
  let out = '';
  for (let i = 0; i < 20; i++) {
    out += chars[arr[i] % chars.length];
  }
  const passInput = document.getElementById('passInput');
  passInput.value = out;
  evaluatePasswordEntropy();
}

function evaluatePasswordEntropy() {
  const pwd = document.getElementById('passInput').value || '';
  if (!pwd) return;

  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;

  const entropy = Math.round(pwd.length * Math.log2(Math.max(pool, 1)));
  document.getElementById('resEntropy').textContent = `${entropy} bits`;

  // Estimación contra 100.000 millones de intentos/seg (Cluster GPU Hashcat)
  const combinations = Math.pow(2, entropy);
  const seconds = combinations / 1e11;

  let timeStr = 'Instantáneo (< 1 seg)';
  let grade = '❌ Muy Débil';
  if (seconds > 31536000 * 1000) {
    timeStr = '+1.000 Siglos (Irrompible)';
    grade = '🛡️ Nivel Militar / Criptográfico';
  } else if (seconds > 31536000) {
    timeStr = `${Math.round(seconds / 31536000)} Años`;
    grade = '✅ Muy Segura';
  } else if (seconds > 86400) {
    timeStr = `${Math.round(seconds / 86400)} Días`;
    grade = '⚠️ Aceptable';
  } else if (seconds > 60) {
    timeStr = `${Math.round(seconds / 60)} Minutos`;
    grade = '❌ Vulnerable';
  }

  document.getElementById('resCrackTime').textContent = timeStr;
  document.getElementById('resPassGrade').textContent = grade;
}

async function updateCryptoHashes() {
  const text = document.getElementById('hashSourceInput').value || '';
  document.getElementById('base64Output').textContent = btoa(unescape(encodeURIComponent(text)));

  const msgBuffer = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('sha256Output').textContent = hashHex;
}

// ==========================================================
// 5. SISTEMA DE MONETIZACIÓN (AMAZON AFILIADOS)
// ==========================================================
const affiliateCatalog = [
  {
    title: 'Alfa Network AWUS036ACH (Wi-Fi Kali Linux)',
    tag: '🔥 TOP AUDITORÍA',
    desc: 'Antena Wi-Fi USB con Modo Monitor e Inyección para prácticas de Ciberseguridad y Pentesting ético.',
    query: 'Alfa+Network+AWUS036ACH+Kali+Linux'
  },
  {
    title: 'SanDisk Ultra 128GB USB 3.0 (Live USB)',
    tag: '⚡ IMPULSO (< 15€)',
    desc: 'Pendrive ultrarrápido para arrancar sistemas en vivo con Ventoy, Kali Linux, Tails o rescate.',
    query: 'SanDisk+Ultra+128GB+USB+3.0'
  },
  {
    title: 'YubiKey 5 NFC — Llave de Seguridad FIDO2',
    tag: '🛡️ ANTI-PHISHING',
    desc: 'Autenticación física en dos pasos (2FA/MFA) por USB y NFC para blindar tus cuentas de hosting y correo.',
    query: 'Yubico+YubiKey+5+NFC'
  },
  {
    title: 'Switch Gestionable Gigabit VLAN (8 Puertos)',
    tag: '🌐 LAB REDES',
    desc: 'El switch más barato para prácticas de segmentación VLAN 802.1Q, QoS y topologías de ASIR/CCNA.',
    query: 'Switch+Gestionable+Gigabit+VLAN+TP-Link+Netgear'
  },
  {
    title: 'Adaptador USB-C a Ethernet Gigabit RJ45',
    tag: '💻 ESENCIAL (< 15€)',
    desc: 'Imprescindible para conectar portátiles modernos a switches y routers en prácticas de laboratorio.',
    query: 'Adaptador+USB-C+a+Ethernet+Gigabit+RJ45'
  },
  {
    title: 'Kit Herramientas Red: Crimpadora + Tester RJ45',
    tag: '🛠️ TÉCNICO FP',
    desc: 'Kit completo con crimpadora, comprobador de pares, pelacables y conectores RJ45 Cat6.',
    query: 'Kit+Crimpadora+Tester+Cable+Red+RJ45'
  },
  {
    title: 'Kit Raspberry Pi 5 (8GB RAM) HomeLab Server',
    tag: '🚀 SERVIDOR CASERO',
    desc: 'Monta tu propio servidor DNS Pi-hole, VPN WireGuard, firewall o Docker en casa.',
    query: 'Raspberry+Pi+5+8GB+Kit'
  }
];

function renderAffiliateProducts() {
  const tag = localStorage.getItem('cibertools_amazon_tag') || 'iagofm-21';
  const container = document.getElementById('affiliateProductsList');

  // Actualizar los enlaces de los banners contextuales dentro de las herramientas
  document.querySelectorAll('.dynamic-amazon-link').forEach((link) => {
    const q = link.dataset.query || 'ciberseguridad+redes';
    link.href = `https://www.amazon.es/s?k=${q}&tag=${encodeURIComponent(tag)}`;
  });

  if (!container) return;
  container.innerHTML = '';
  affiliateCatalog.forEach((item) => {
    const url = `https://www.amazon.es/s?k=${item.query}&tag=${encodeURIComponent(tag)}`;
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'product-item';
    a.innerHTML = `
      <div class="prod-top">
        <span class="prod-title">${item.title}</span>
        <span class="prod-tag">${item.tag}</span>
      </div>
      <div class="prod-desc">${item.desc}</div>
      <div class="prod-cta">👉 Comprobar oferta actual en Amazon.es →</div>
    `;
    container.appendChild(a);
  });
}

function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2100);
}

// ==========================================================
// INICIALIZACIÓN DE EVENTOS
// ==========================================================
document.addEventListener('DOMContentLoaded', () => {
  // Pestañas de herramientas
  document.querySelectorAll('.nav-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-tab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.tool-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tool-${btn.dataset.tool}`).classList.add('active');
    });
  });

  // 1. Subredes & VLSM
  document.getElementById('ipInput').addEventListener('input', updateSubnetCalc);
  document.getElementById('cidrInput').addEventListener('change', updateSubnetCalc);
  document.getElementById('calcVlsmBtn').addEventListener('click', calculateVlsmTable);
  updateSubnetCalc();
  calculateVlsmTable();

  // 2. SPF / DMARC
  ['dmarcDomain', 'spfProvider', 'dmarcPolicy', 'dmarcEmail'].forEach((id) => {
    document.getElementById(id).addEventListener('input', updateDmarcGenerator);
    document.getElementById(id).addEventListener('change', updateDmarcGenerator);
  });
  updateDmarcGenerator();

  // 3. Nmap & Puertos
  ['nmapTarget', 'nmapScanType', 'nmapSpeed', 'nmapSv', 'nmapOs', 'nmapSc', 'nmapVuln', 'nmapAllPorts', 'nmapPn'].forEach((id) => {
    document.getElementById(id).addEventListener('input', updateNmapBuilder);
    document.getElementById(id).addEventListener('change', updateNmapBuilder);
  });
  document.getElementById('portSearchInput').addEventListener('input', (e) => renderPortsTable(e.target.value));
  updateNmapBuilder();
  renderPortsTable();

  // 4. Contraseñas y Hashes
  document.getElementById('genPassBtn').addEventListener('click', generateStrongPassword);
  document.getElementById('passInput').addEventListener('input', evaluatePasswordEntropy);
  document.getElementById('hashSourceInput').addEventListener('input', updateCryptoHashes);
  generateStrongPassword();
  updateCryptoHashes();

  // 5. Copiar al portapapeles
  document.querySelectorAll('.btn-copy').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.copy);
      if (!target) return;
      const val = target.value !== undefined ? target.value : target.textContent;
      navigator.clipboard.writeText(val).then(() => showToast('✅ ¡Copiado al portapapeles!'));
    });
  });

  // 6. Modal de Afiliados
  const modal = document.getElementById('affiliateModal');
  const tagInput = document.getElementById('amazonTagInput');
  tagInput.value = localStorage.getItem('cibertools_amazon_tag') || 'iagofm-21';

  document.getElementById('openAffiliateConfigBtn').addEventListener('click', () => modal.classList.remove('hidden'));
  document.getElementById('closeModalBtn').addEventListener('click', () => modal.classList.add('hidden'));
  document.getElementById('saveAffiliateBtn').addEventListener('click', () => {
    localStorage.setItem('cibertools_amazon_tag', tagInput.value.trim() || 'iagofm-21');
    renderAffiliateProducts();
    modal.classList.add('hidden');
    showToast('💰 ID de Afiliado de Amazon actualizado');
  });

  renderAffiliateProducts();
});
