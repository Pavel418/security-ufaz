// static/js/home.js
const qs = (s, r = document) => r.querySelector(s);
const qsa = (s, r = document) => Array.from(r.querySelectorAll(s));

const fileInput = qs('#file-upload');
const dropzone = qs('#dropzone');
const fileNameDiv = qs('#file-name');
const analyzeBtn = qs('#analyze-btn');
const messageDiv = qs('#message');
const analysisResult = qs('#analysis-result');
const cardsContainer = qs('#attack-cards');
const downloadReportBtn = qs('#download-report-btn'); // NEW

const metricFile = qs('#metric-file');
const metricGroups = qs('#metric-groups');
const metricScans = qs('#metric-scans');
const metricPackets = qs('#metric-packets');
const metricEmitted = qs('#metric-emitted');
const metricEnriched = qs('#metric-enriched');

const csrfToken = () => (qs('meta[name="csrf-token"]')?.content || '');

function setAnalyzeEnabled(on){
  analyzeBtn.disabled = !on;
  analyzeBtn.setAttribute('aria-disabled', String(!on));
  analyzeBtn.classList.toggle('glow', !!on);
}
function showMessage(text, type){
  messageDiv.textContent = String(text ?? '');
  messageDiv.className = `message ${type}`;
  messageDiv.hidden = false;
}
function hideMessage(){ messageDiv.hidden = true; }

function esc(s){
  return String(s ?? "")
    .replace(/[&<>"'`=\/]/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','/':'&#x2F;','`':'&#x60;','=':'&#x3D;'}[c])
    );
}
function numOrDash(v){
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString() : '—';
}
function textOrDash(v){
  return v === 0 ? '0' : (v ? String(v) : '—');
}

function renderDetections(items){
  if (!Array.isArray(items) || items.length === 0){
    return `
      <div class="analysis-item">
        <div class="analysis-label">Detections</div>
        <div class="analysis-value">No detections</div>
      </div>
    `;
  }
  return items.map(x => {
    const tactic = esc(x.tactic_name);
    const techId = esc(x.technique_id);
    const techName = esc(x.technique_name);
    const reason = esc(x.reason);
    const score = (typeof x.score === 'number') ? x.score.toFixed(2) : esc(x.score);
    const relevance = (typeof x.relevance === 'number') ? x.relevance.toFixed(2) : esc(x.relevance);
    const impact = (typeof x.impact === 'number') ? x.impact.toFixed(2) : esc(x.impact);
    return `
      <div class="analysis-item">
        <div class="analysis-label">Tactic</div>
        <div class="analysis-value analysis-value--large">${tactic || '—'}</div>

        <div class="analysis-label">Technique</div>
        <div class="analysis-value">${techId || '—'}${techName ? ' — ' + techName : ''}</div>

        <div class="analysis-label">Reason</div>
        <div class="analysis-value analysis-value--reason">${reason || '—'}</div>

        <div style="display:flex; gap:16px; margin-top:12px;">
          <div>
            <div class="analysis-label">Score</div>
            <div class="analysis-value">${textOrDash(score)}</div>
          </div>
          <div>
            <div class="analysis-label">Relevance</div>
            <div class="analysis-value">${textOrDash(relevance)}</div>
          </div>
          <div>
            <div class="analysis-label">Impact</div>
            <div class="analysis-value">${textOrDash(impact)}</div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function displayAnalysis(analysis){
  analysisResult.hidden = false;

  const pcap = esc(analysis.pcap_file || analysis.filename || '—');
  const groups = numOrDash(analysis.groups);
  const scans = numOrDash(analysis.scans);
  const metrics = analysis.metrics || {};

  const mPackets = textOrDash(metrics.packets_processed);
  const mEmitted = textOrDash(metrics.groups_emitted ?? analysis.groups);
  const mEnriched = textOrDash(metrics.http_enriched);

  metricFile.innerHTML = pcap;
  metricGroups.textContent = groups;
  metricScans.textContent = scans;
  metricPackets.textContent = mPackets;
  metricEmitted.textContent = mEmitted;
  metricEnriched.textContent = mEnriched;

  cardsContainer.innerHTML = renderDetections(analysis.final_answer);

  // Enable report download after we have analysis
  if (downloadReportBtn){
    downloadReportBtn.hidden = false;
    downloadReportBtn.ariaHidden = 'false';
  }
}

async function uploadFile(file){
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/upload', {
      method: 'POST',
      body: formData,
      credentials: 'same-origin',
      headers: {'X-CSRF-Token': csrfToken()}
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.success){
      showMessage(data.message || 'Upload successful.', 'success');
      setAnalyzeEnabled(true);
    } else {
      const extra = data.allowed ? ` (Allowed: ${data.allowed.join(', ')})` : '';
      showMessage((data.error || 'Upload failed.') + extra, 'error');
      setAnalyzeEnabled(false);
    }
  } catch (err){
    showMessage('Upload failed: ' + (err?.message || err), 'error');
    setAnalyzeEnabled(false);
  }
}

let analyzing = false;
async function analyze(){
  if (analyzing) return;
  analyzing = true;
  setAnalyzeEnabled(false);
  const prev = analyzeBtn.innerHTML;
  analyzeBtn.innerHTML = '⏳ Analyzing...';

  try {
    const res = await fetch('/analyze', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'X-CSRF-Token': csrfToken()}
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data?.success){
      showMessage('Analysis complete!', 'success');
      displayAnalysis(data.analysis || {});
    } else {
      showMessage(data?.error || 'Analysis failed', 'error');
    }
  } catch (err){
    showMessage('Analysis failed: ' + (err?.message || err), 'error');
  } finally {
    analyzeBtn.innerHTML = prev;
    setAnalyzeEnabled(true);
    analyzing = false;
  }
}

// NEW: build & download PDF report from the latest home-page analysis
async function downloadReport(){
  try{
    downloadReportBtn.disabled = true;
    downloadReportBtn.innerHTML = '⏳ Building Report...';
    const res = await fetch('/report/generate', {
      method: 'POST',
      headers: {'Content-Type':'application/json','X-CSRF-Token': csrfToken()},
      credentials: 'same-origin',
      body: JSON.stringify({ title: 'Network Log Analysis Report' }) // optional
    });
    const data = await res.json();
    if (!res.ok || !data?.success || !data?.url){
      throw new Error(data?.error || `HTTP ${res.status}`);
    }
    // Trigger browser download
    const a = document.createElement('a');
    a.href = data.url;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }catch(err){
    showMessage('Report build failed: ' + (err?.message || err), 'error');
  }finally{
    downloadReportBtn.disabled = false;
    downloadReportBtn.innerHTML = '<span class="icon" aria-hidden="true">📄</span>Download Report (PDF)';
  }
}

fileInput.addEventListener('change', (e)=>{
  const file = e.target.files?.[0];
  if (!file) return;
  fileNameDiv.textContent = `Selected: ${file.name}`;
  fileNameDiv.style.display = 'block';
  uploadFile(file);
});
['dragenter','dragover'].forEach(evt =>
  dropzone.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('dragging'); })
);
['dragleave','drop'].forEach(evt =>
  dropzone.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('dragging'); })
);
dropzone.addEventListener('drop', (e)=>{
  const file = e.dataTransfer?.files?.[0];
  if (!file) return;
  fileNameDiv.textContent = `Selected: ${file.name}`;
  fileNameDiv.style.display = 'block';
  uploadFile(file);
});
dropzone.addEventListener('keydown', (e)=>{ if (e.key==='Enter' || e.key===' ') { e.preventDefault(); fileInput.click(); } });
dropzone.addEventListener('click', ()=> fileInput.click());

analyzeBtn.addEventListener('click', analyze);
downloadReportBtn?.addEventListener('click', downloadReport);