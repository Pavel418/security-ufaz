// static/js/stream.js
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

let isStreaming = false;
let streamInterval = null;
let chart = null;
let selectedInterface = null;
let hasPcapFile = false;

const startBtn = $('#start-btn');
const stopBtn = $('#stop-btn');
const analyzePcapBtn = $('#analyze-pcap-btn');
const statusDiv = $('#status');
const analysisResult = $('#analysis-result');
const analysisGrid = $('#analysis-grid');
const errorAlertDiv = $('#error-alert');
const interfaceListDiv = $('#interface-list');
const selectedInterfaceSpan = $('#selected-interface');

const statTotal = $('#stat-total');
const statPps = $('#stat-pps');
const statBw = $('#stat-bandwidth');
const statTime = $('#stat-time');

const detectNowBtn = $('#detect-now-btn');
const detectionsSection = $('#detections');
const detectionsContent = $('#detections-content');

// NEW: report download button on stream page
const downloadReportStreamBtn = $('#download-report-stream-btn');

const csrfToken = () => ($('meta[name="csrf-token"]')?.content || '');

function esc(s){
  return String(s ?? "")
    .replace(/[&<>"'`=\/]/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','/':'&#x2F;','`':'&#x60;','=':'&#x3D;'}[c])
    );
}
const num = v => Number(v);
const fmt = v => Number.isFinite(v) ? v.toLocaleString() : '—';

window.addEventListener('DOMContentLoaded', () => {
  loadInterfaces();
  setupChart();
});

async function loadInterfaces() {
  try {
    const response = await fetch('/stream/interfaces', {credentials:'same-origin'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();

    if (result.success && Array.isArray(result.interfaces) && result.interfaces.length > 0) {
      displayInterfaces(result.interfaces);
    } else {
      interfaceListDiv.className = '';
      interfaceListDiv.innerHTML = `
        <div class="no-interfaces">
          <strong>⚠️ No network interfaces found</strong>
          <p>Make sure you're running with administrator privileges.</p>
        </div>`;
    }
  } catch (error) {
    interfaceListDiv.className = '';
    interfaceListDiv.innerHTML = `
      <div class="no-interfaces">
        <strong>❌ Error loading interfaces</strong>
        <p>${esc(error.message)}</p>
      </div>`;
  }
}

function displayInterfaces(interfaces) {
  interfaceListDiv.innerHTML = '';
  interfaceListDiv.className = 'interface-grid';

  interfaces.forEach(iface => {
    const option = document.createElement('div');
    option.className = 'interface-option';
    option.innerHTML = `
      <div class="interface-name">${esc(iface)}</div>
      <div class="interface-status">Click to select</div>`;
    option.addEventListener('click', () => selectInterface(iface, option));
    interfaceListDiv.appendChild(option);
  });
}

function selectInterface(iface, element) {
  $$('.interface-option').forEach(opt => opt.classList.remove('selected'));
  element.classList.add('selected');
  selectedInterface = iface;
  selectedInterfaceSpan.textContent = iface;
  startBtn.disabled = false;
  detectNowBtn.disabled = false; // allow manual detection after an interface is chosen
}

function setupChart(){
  const ctx = $('#streamChart').getContext('2d');
  chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Bandwidth (Mbps)',
        data: [],
        tension: 0.4, fill: true, borderWidth: 2, pointRadius: 3, pointHoverRadius: 5, yAxisID: 'y'
      }, {
        label: 'Packets/sec',
        data: [],
        tension: 0.4, fill: true, borderWidth: 2, pointRadius: 3, pointHoverRadius: 5, yAxisID: 'y1'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: '#e2e8f0', font: { size: 14, weight: '600' }, padding: 15 } },
        tooltip: {
          backgroundColor: '#0f172a', borderColor: '#3b82f6', borderWidth: 2,
          titleColor: '#f1f5f9', bodyColor: '#e2e8f0', padding: 12, displayColors: true,
          callbacks: {
            label: (ctx) => {
              let v = Number(ctx.parsed.y);
              let unit = ctx.datasetIndex === 0 ? ' Mbps' : ' pps';
              return (ctx.dataset.label || '') + ': ' + (Number.isFinite(v) ? v.toFixed(2) : v) + unit;
            }
          }
        }
      },
      scales: {
        x: {
          ticks: { color: '#94a3b8', maxRotation: 45, minRotation: 45, font: { size: 11 } },
          grid: { color: '#334155', drawBorder: false }
        },
        y: {
          type: 'linear', position: 'left', beginAtZero: true,
          title: { display: true, text: 'Bandwidth (Mbps)', color: '#3b82f6', font: { weight: '700', size: 13 } },
          ticks: { color: '#94a3b8', font: { size: 11 } },
          grid: { color: '#334155', drawBorder: false }
        },
        y1: {
          type: 'linear', position: 'right', beginAtZero: true,
          title: { display: true, text: 'Packets/Second', color: '#06b6d4', font: { weight: '700', size: 13 } },
          ticks: { color: '#94a3b8', font: { size: 11 } },
          grid: { drawOnChartArea: false, color: '#334155', drawBorder: false }
        }
      },
      animation: { duration: 300 }
    }
  });
}

startBtn.addEventListener('click', startStreaming);
stopBtn.addEventListener('click', stopStreaming);
analyzePcapBtn.addEventListener('click', analyzeSavedPcap);

async function startStreaming() {
  if (!selectedInterface) {
    alert('Please select a network interface first');
    return;
  }

  try {
    const response = await fetch('/stream/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json','X-CSRF-Token': csrfToken()},
      credentials: 'same-origin',
      body: JSON.stringify({ interface: selectedInterface })
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();
    if (!result.success) {
      alert('Error starting stream: ' + (result.error || 'Unknown error'));
      return;
    }

    isStreaming = true;
    startBtn.disabled = true;
    stopBtn.disabled = false;
    statusDiv.innerHTML = `<span class="icon" aria-hidden="true">🔴</span>Network Stream Active on ${esc(selectedInterface)} - Capturing Packets`;
    statusDiv.className = 'status streaming';
    analysisResult.hidden = true;
    analysisGrid.innerHTML = '';
    hideError();

    $('#interface-selection').style.opacity = '0.5';
    $('#interface-selection').style.pointerEvents = 'none';

    chart.data.labels = [];
    chart.data.datasets[0].data = [];
    chart.data.datasets[1].data = [];
    chart.update();

    streamInterval = setInterval(fetchStreamData, 1000);
  } catch (error) {
    alert('Failed to start stream: ' + error.message);
  }
}

async function fetchStreamData() {
  try {
    const response = await fetch('/stream/data', {credentials:'same-origin'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    if (data.error) {
      showError(data.error);
      stopStreaming();
      return;
    }

    statTotal.textContent = fmt(num(data.total_packets));
    statPps.innerHTML = `${Number(num(data.packets_per_second)).toFixed(2)}<span class="stat-unit">pps</span>`;
    statBw.innerHTML = `${Number(num(data.bandwidth)).toFixed(2)}<span class="stat-unit">Mbps</span>`;
    statTime.innerHTML = `${Number(num(data.elapsed_time)).toFixed(1)}<span class="stat-unit">s</span>`;

    const time = new Date(data.timestamp).toLocaleTimeString();
    chart.data.labels.push(time);
    chart.data.datasets[0].data.push(Number(num(data.bandwidth)));
    chart.data.datasets[1].data.push(Number(num(data.packets_per_second)));

    if (chart.data.labels.length > 30) {
      chart.data.labels.shift();
      chart.data.datasets[0].data.shift();
      chart.data.datasets[1].data.shift();
    }
    chart.update('none');
  } catch (error) {
    // swallow polling errors to keep UI smooth
  }
}

function showError(errorMessage) {
  errorAlertDiv.hidden = false;
  errorAlertDiv.className = 'error-alert';
  errorAlertDiv.innerHTML = `
    <h3>⚠️ Packet Capture Error</h3>
    <p><strong>Error:</strong> ${esc(errorMessage)}</p>
    <p><strong>Solution:</strong> Run the backend with administrator privileges:</p>
    <p><code>sudo python app.py</code></p>
    <p>This is required for network packet capture.</p>`;
}
function hideError(){ errorAlertDiv.hidden = true; }

async function stopStreaming() {
  isStreaming = false;
  clearInterval(streamInterval);
  startBtn.disabled = false;
  stopBtn.disabled = true;
  statusDiv.innerHTML = '<span class="icon" aria-hidden="true">⏸️</span>Stream Stopped - Processing Analysis';
  statusDiv.className = 'status stopped';

  $('#interface-selection').style.opacity = '1';
  $('#interface-selection').style.pointerEvents = 'auto';

  try {
    const response = await fetch('/stream/stop', {
      method: 'POST',
      headers: {'Content-Type':'application/json','X-CSRF-Token': csrfToken()},
      credentials:'same-origin'
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();

    if (result.success) {
      displayAnalysis(result.analysis);
      statusDiv.innerHTML = '<span class="icon" aria-hidden="true">✅</span>Analysis Complete';
      hasPcapFile = true;
      analyzePcapBtn.hidden = false;
    }
  } catch (error) {
    showError(error.message);
  }
}

function displayAnalysis(a = {}) {
  analysisResult.hidden = false;

  const html = `
    <div class="analysis-item">
      <div class="analysis-label">Total Packets</div>
      <div class="analysis-value">${fmt(a.total_packets_captured)}</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Capture Duration</div>
      <div class="analysis-value">${esc(a.capture_duration)} s</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Data Points</div>
      <div class="analysis-value">${fmt(a.data_points)}</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Avg Bandwidth</div>
      <div class="analysis-value">${esc(a.average_bandwidth_mbps)} Mbps</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Peak Bandwidth</div>
      <div class="analysis-value">${esc(a.peak_bandwidth_mbps)} Mbps</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Min Bandwidth</div>
      <div class="analysis-value">${esc(a.min_bandwidth_mbps)} Mbps</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Avg Packets/Sec</div>
      <div class="analysis-value">${esc(a.avg_packets_per_second)} pps</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Peak Packets/Sec</div>
      <div class="analysis-value">${esc(a.peak_packets_per_second)} pps</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">PCAP File (Wireshark)</div>
      <div class="analysis-value analysis-value--mono">${esc(a.pcap_file)}</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Analysis JSON</div>
      <div class="analysis-value analysis-value--mono">${esc(a.analysis_file)}</div>
    </div>`;
  analysisGrid.innerHTML = html;
}

async function analyzeSavedPcap() {
  analyzePcapBtn.disabled = true;
  statusDiv.innerHTML = '<span class="icon" aria-hidden="true">🔍</span>Analyzing Saved PCAP File...';
  statusDiv.className = 'status streaming';

  try {
    const response = await fetch('/stream/analyze-pcap', {
      method: 'POST',
      headers: {'Content-Type':'application/json','X-CSRF-Token': csrfToken()},
      credentials:'same-origin'
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();

    if (result.success) {
      displayDetailedAnalysis(result.analysis);
      statusDiv.innerHTML = '<span class="icon" aria-hidden="true">✅</span>PCAP Analysis Complete';
      statusDiv.className = 'status stopped';
    } else {
      alert('Error analyzing PCAP: ' + (result.error || 'Unknown error'));
      statusDiv.innerHTML = '<span class="icon" aria-hidden="true">❌</span>Analysis Failed';
    }
  } catch (error) {
    alert('Failed to analyze PCAP: ' + error.message);
    statusDiv.innerHTML = '<span class="icon" aria-hidden="true">❌</span>Analysis Failed';
  } finally {
    analyzePcapBtn.disabled = false;
  }
}

function displayDetailedAnalysis(analysis = {}) {
  const protocolTotal = Object.values(analysis.protocol_distribution || {}).reduce((a, b) => a + b, 0);

  let protocolBars = '';
  for (const [protocol, count] of Object.entries(analysis.protocol_distribution || {})) {
    const percentage = protocolTotal ? ((count / protocolTotal) * 100).toFixed(1) : '0.0';
    protocolBars += `
      <div class="protocol-bar">
        <div class="protocol-label">${esc(protocol)}</div>
        <div class="protocol-bar-fill" style="width:${percentage}%"></div>
        <div class="protocol-count">${fmt(count)} (${percentage}%)</div>
      </div>`;
  }

  const topList = (arr=[]) => arr.map(item => `
    <li class="ip-item">
      <span class="ip-address">${esc(item.ip)}</span>
      <span class="ip-count">${fmt(item.count)} packets</span>
    </li>`).join('');

  analysisResult.hidden = false;
  analysisGrid.innerHTML = `
    <div class="analysis-item">
      <div class="analysis-label">Total Packets</div>
      <div class="analysis-value">${fmt(analysis.total_packets)}</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Total Size</div>
      <div class="analysis-value">${esc(analysis.total_size_mb)} MB</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Unique Sources</div>
      <div class="analysis-value">${fmt(analysis.unique_sources)}</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Unique Destinations</div>
      <div class="analysis-value">${fmt(analysis.unique_destinations)}</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">PCAP File</div>
      <div class="analysis-value analysis-value--mono">${esc(analysis.pcap_file)}</div>
    </div>
    <div class="analysis-item">
      <div class="analysis-label">Analyzed At</div>
      <div class="analysis-value analysis-value--mono">${esc(analysis.analyzed_at)}</div>
    </div>
    <div class="analysis-item" style="grid-column:1 / -1;">
      <div class="protocol-chart">
        <h4 class="analysis-section-title">Protocol Distribution</h4>
        ${protocolBars}
      </div>
    </div>
    <div class="analysis-item" style="grid-column:1 / -1;">
      <div class="protocol-chart">
        <h4 class="analysis-section-title">Top Source IPs</h4>
        <ul class="ip-list">${topList(analysis.top_source_ips)}</ul>
      </div>
    </div>
    <div class="analysis-item" style="grid-column:1 / -1;">
      <div class="protocol-chart">
        <h4 class="analysis-section-title">Top Destination IPs</h4>
        <ul class="ip-list">${topList(analysis.top_destination_ips)}</ul>
      </div>
    </div>`;
}

/* Detection: manual only */
detectNowBtn.addEventListener('click', async () => {
  if (!selectedInterface) {
    alert('Please select a network interface first');
    return;
  }
  detectNowBtn.disabled = true;
  try {
    const res = await fetch('/detect/run-now', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-CSRF-Token': csrfToken()},
      credentials:'same-origin',
      body: JSON.stringify({ duration: 10, interface: selectedInterface })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const js = await res.json();
    if (!js.success) throw new Error(js.error || 'Detection failed');

    // Render detections to the section
    const items = Array.isArray(js.data?.final_answer) ? js.data.final_answer : [];
    detectionsSection.hidden = false;
    detectionsContent.innerHTML = items.length ? items.map(renderCard).join('') : `
      <div class="analysis-item" style="grid-column:1 / -1;">
        <div class="analysis-label">Status</div>
        <div class="analysis-value">No detections</div>
      </div>`;

    // Enable report button once detections are available
    if (downloadReportStreamBtn){
      downloadReportStreamBtn.hidden = false;
      downloadReportStreamBtn.ariaHidden = 'false';
    }
  } catch (e) {
    alert('Detection failed: ' + e.message);
  } finally {
    detectNowBtn.disabled = false;
  }
});

function renderCard(x){
  const tactic = esc(x.tactic_name ?? '—');
  const techId = esc(x.technique_id ?? '—');
  const techName = esc(x.technique_name ?? '—');
  const reason = esc(x.reason ?? '—');
  const score = typeof x.score === 'number' ? x.score.toFixed(2) : '—';
  const rel = typeof x.relevance === 'number' ? x.relevance.toFixed(2) : '—';
  const imp = typeof x.impact === 'number' ? x.impact.toFixed(2) : '—';
  return `
    <div class="analysis-item">
      <div class="analysis-label">Tactic</div>
      <div class="analysis-value analysis-value--large">${tactic}</div>

      <div class="analysis-label">Technique</div>
      <div class="analysis-value">${techId} — ${techName}</div>

      <div class="analysis-label">Reason</div>
      <div class="analysis-value">${reason}</div>

      <div style="display:flex; gap:12px; margin-top:12px;">
        <div>
          <div class="analysis-label">Score</div>
          <div class="analysis-value">${score}</div>
        </div>
        <div>
          <div class="analysis-label">Relevance</div>
          <div class="analysis-value">${rel}</div>
        </div>
        <div>
          <div class="analysis-label">Impact</div>
          <div class="analysis-value">${imp}</div>
        </div>
      </div>
    </div>`;
}

// NEW: build & download PDF report from the latest stream detections
async function downloadStreamReport(){
  try{
    downloadReportStreamBtn.disabled = true;
    downloadReportStreamBtn.innerHTML = '⏳ Building Report...';
    const res = await fetch('/report/generate', {
      method: 'POST',
      headers: {'Content-Type':'application/json','X-CSRF-Token': csrfToken()},
      credentials: 'same-origin',
      body: JSON.stringify({ title: 'Network Stream Detection Report' }) // optional
    });
    const data = await res.json();
    if (!res.ok || !data?.success || !data?.url){
      throw new Error(data?.error || `HTTP ${res.status}`);
    }
    const a = document.createElement('a');
    a.href = data.url;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }catch(err){
    alert('Report build failed: ' + (err?.message || err));
  }finally{
    downloadReportStreamBtn.disabled = false;
    downloadReportStreamBtn.innerHTML = '<span class="icon" aria-hidden="true">📄</span>Download Report (PDF)';
  }
}

downloadReportStreamBtn?.addEventListener('click', downloadStreamReport);