/**
 * VISIONCORE — Defect Analysis System
 * app.js  |  Netlify Identity + Serverless Function edition
 *
 * Auth flow:
 *   1. Netlify Identity widget handles login/signup
 *   2. On login, JWT token is obtained and stored in memory
 *   3. All image analysis calls go to /.netlify/functions/analyze
 *      with the JWT in Authorization header
 *   4. Server-side function holds the Anthropic API key
 */

"use strict";

/* ═══════════════════════════════════════
   APP STATE
═══════════════════════════════════════ */

const state = {
  user:      null,   // Netlify Identity user object
  token:     null,   // JWT for API calls
  images:    [],     // [{ id, file, url, name }]
  results:   {},     // { [id]: resultObj | { error } }
  analyzing: {},     // { [id]: bool }
  activeId:  null,
};

/* ═══════════════════════════════════════
   DOM REFERENCES
═══════════════════════════════════════ */

const $  = (id) => document.getElementById(id);
const el = {
  loginGate:       $("login-gate"),
  loginBtn:        $("login-btn"),
  app:             $("app"),
  logoutBtn:       $("logout-btn"),
  userInfo:        $("user-info"),

  fileInput:       $("file-input"),
  addBtn:          $("add-btn"),
  dropZone:        $("drop-zone"),

  imageList:       $("image-list"),
  imageCount:      $("image-count"),
  queueCount:      $("queue-count"),

  workspace:       $("workspace"),

  viewerFilename:  $("viewer-filename"),
  confidenceMeta:  $("confidence-meta"),
  previewImg:      $("preview-img"),
  classifBadge:    $("classification-badge"),
  scanOverlay:     $("scan-overlay"),

  resPlaceholder:  $("results-placeholder"),
  resLoading:      $("results-loading"),
  resError:        $("results-error"),
  resContent:      $("results-content"),

  resClassBlock:   $("res-classification-block"),
  resClassVal:     $("res-classification"),
  resConfPct:      $("res-confidence-pct"),
  resConfFill:     $("res-confidence-fill"),
  resSummary:      $("res-summary"),
  resDefectsWrap:  $("res-defects-wrap"),
  resDefectCount:  $("res-defect-count"),
  resDefectsList:  $("res-defects-list"),
  resRecommend:    $("res-recommendation"),
};

/* ═══════════════════════════════════════
   NETLIFY IDENTITY — AUTH
═══════════════════════════════════════ */

function initAuth() {
  const netlifyIdentity = window.netlifyIdentity;

  // ── Widget failed to load (script blocked / offline)
  if (!netlifyIdentity) {
    setLoginStatus("error", "Identity widget failed to load. Check your connection.");
    return;
  }

  // ── Disable button until widget is fully initialised
  setLoginStatus("loading", "INITIALIZING...");

  // ── CRITICAL: handle email confirmation / password-recovery tokens
  // Netlify appends #confirmation_token=xxx or #recovery_token=xxx to the URL
  // after a user clicks their confirmation email. The widget must see this URL
  // to complete registration — we call init() AFTER registering all handlers.
  netlifyIdentity.on("init", (user) => {
    if (user) {
      // Already logged-in session found (e.g. page refresh)
      handleLogin(user);
    } else {
      // Ready — enable the button
      setLoginStatus("ready", "SIGN IN / REGISTER");
    }
  });

  // ── Successful login or signup confirmation
  netlifyIdentity.on("login", (user) => {
    netlifyIdentity.close();
    handleLogin(user);
  });

  // ── Logout
  netlifyIdentity.on("logout", () => handleLogout());

  // ── Errors (wrong password, unconfirmed email, etc.)
  netlifyIdentity.on("error", (err) => {
    console.error("Netlify Identity error:", err);
    setLoginStatus("ready", "SIGN IN / REGISTER");
  });

  // ── Now init — widget reads the URL hash for confirmation tokens here
  netlifyIdentity.init({ locale: "en" });

  // ── Button click — safe to call open() after init fires (button is
  //    disabled until then, so this handler won't fire prematurely)
  el.loginBtn.addEventListener("click", () => {
    netlifyIdentity.open("login");
  });

  // ── Sign out
  el.logoutBtn.addEventListener("click", () => netlifyIdentity.logout());
}

/**
 * Update login button appearance.
 * @param {"loading"|"ready"|"error"} status
 * @param {string} label
 */
function setLoginStatus(status, label) {
  const btn = el.loginBtn;
  btn.disabled = status === "loading" || status === "error";

  if (status === "loading") {
    btn.innerHTML = `<span class="login-btn-spinner"></span> ${label}`;
    btn.style.opacity = "0.6";
    btn.style.cursor  = "not-allowed";
  } else if (status === "error") {
    btn.innerHTML = `✕ ${label}`;
    btn.style.opacity = "0.5";
    btn.style.cursor  = "not-allowed";
    btn.style.borderColor = "var(--red)";
    btn.style.color       = "var(--red)";
  } else {
    btn.innerHTML = `<span class="login-btn-icon">→</span> ${label}`;
    btn.style.opacity = "1";
    btn.style.cursor  = "pointer";
    btn.style.borderColor = "";
    btn.style.color       = "";
  }
}

async function handleLogin(user) {
  state.user = user;

  // Get JWT token for API calls
  try {
    // token() returns a fresh token, refreshing if needed
    state.token = await user.jwt();
  } catch (e) {
    console.error("Failed to get JWT:", e);
  }

  // Show user email in header
  el.userInfo.textContent = user.email || "";

  showApp();
}

function handleLogout() {
  state.user  = null;
  state.token = null;
  // Clear all state
  state.images.forEach((img) => URL.revokeObjectURL(img.url));
  state.images    = [];
  state.results   = {};
  state.analyzing = {};
  state.activeId  = null;

  showLoginGate();
}

function showLoginGate() {
  el.app.classList.add("hidden");
  el.loginGate.classList.remove("hidden");
  // Re-enable the button when returning to login screen
  setLoginStatus("ready", "SIGN IN / REGISTER");
}

function showApp() {
  el.loginGate.classList.add("hidden");
  el.app.classList.remove("hidden");
  updateDropZoneVisibility();
  renderSidebar();
}

/* ═══════════════════════════════════════
   FILE HANDLING
═══════════════════════════════════════ */

el.addBtn.addEventListener("click",  () => el.fileInput.click());
el.dropZone.addEventListener("click", () => el.fileInput.click());

el.fileInput.addEventListener("change", (e) => {
  addImages(e.target.files);
  e.target.value = "";
});

el.dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  el.dropZone.classList.add("drag-over");
});
el.dropZone.addEventListener("dragleave", () => {
  el.dropZone.classList.remove("drag-over");
});
el.dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  el.dropZone.classList.remove("drag-over");
  addImages(e.dataTransfer.files);
});

document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => {
  e.preventDefault();
  if (state.user) addImages(e.dataTransfer.files);
});

function addImages(fileList) {
  const files = Array.from(fileList).filter((f) => f.type.startsWith("image/"));
  if (!files.length) return;

  const newImgs = files.map((file) => ({
    id:   `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    file,
    url:  URL.createObjectURL(file),
    name: file.name,
  }));

  newImgs.forEach((img) => state.images.push(img));
  setActive(newImgs[0].id);
  renderSidebar();
  updateDropZoneVisibility();
  newImgs.forEach(analyzeImage);
}

function removeImage(id) {
  const idx = state.images.findIndex((i) => i.id === id);
  if (idx === -1) return;
  URL.revokeObjectURL(state.images[idx].url);
  state.images.splice(idx, 1);
  delete state.results[id];
  delete state.analyzing[id];
  if (state.activeId === id) state.activeId = state.images[0]?.id || null;
  renderSidebar();
  renderViewer();
  renderResults();
  updateDropZoneVisibility();
  updateHeaderQueue();
}

/* ═══════════════════════════════════════
   ANALYSIS — calls Netlify function
═══════════════════════════════════════ */

async function toBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = () => resolve(reader.result.split(",")[1]);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function analyzeImage(imgObj) {
  state.analyzing[imgObj.id] = true;
  updateHeaderQueue();
  renderSidebarItem(imgObj.id);
  if (state.activeId === imgObj.id) renderResults();

  try {
    // Refresh token before each request (handles expiry)
    if (state.user) {
      state.token = await state.user.jwt();
    }

    const imageBase64 = await toBase64(imgObj.file);
    const mediaType   = imgObj.file.type || "image/jpeg";

    const response = await fetch("/.netlify/functions/analyze", {
      method: "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${state.token}`,
      },
      body: JSON.stringify({ imageBase64, mediaType }),
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }

    state.results[imgObj.id] = data;

  } catch (err) {
    state.results[imgObj.id] = { error: `Analysis failed: ${err.message}` };
  }

  state.analyzing[imgObj.id] = false;
  updateHeaderQueue();
  renderSidebarItem(imgObj.id);
  if (state.activeId === imgObj.id) {
    renderViewer();
    renderResults();
  }
}

/* ═══════════════════════════════════════
   ACTIVE IMAGE
═══════════════════════════════════════ */

function setActive(id) {
  state.activeId = id;
  renderSidebar();
  renderViewer();
  renderResults();
}

/* ═══════════════════════════════════════
   RENDER — SIDEBAR
═══════════════════════════════════════ */

function renderSidebar() {
  el.imageCount.textContent = state.images.length;
  el.imageList.innerHTML    = "";
  state.images.forEach((img) => el.imageList.appendChild(buildSidebarItem(img)));
}

function renderSidebarItem(id) {
  const existing = el.imageList.querySelector(`[data-id="${id}"]`);
  const img      = state.images.find((i) => i.id === id);
  if (!img) return;
  const newItem  = buildSidebarItem(img);
  if (existing) existing.replaceWith(newItem);
}

function buildSidebarItem(img) {
  const res      = state.results[img.id];
  const isActive = state.activeId === img.id;
  const isLoad   = state.analyzing[img.id];

  const div      = document.createElement("div");
  div.className  = `sidebar-item${isActive ? " active" : ""}`;
  div.dataset.id = img.id;

  let statusHtml;
  if (isLoad) {
    statusHtml = `<span class="sidebar-status status-scanning">⟳ Scanning...</span>`;
  } else if (res?.classification) {
    const c = res.classification === "FAULTY" ? "faulty" : "ok";
    statusHtml = `<span class="sidebar-status status-${c}">● ${res.classification}</span>`;
  } else if (res?.error) {
    statusHtml = `<span class="sidebar-status status-error">✕ Error</span>`;
  } else {
    statusHtml = `<span class="sidebar-status status-scanning">— Pending</span>`;
  }

  div.innerHTML = `
    <img class="sidebar-thumb" src="${img.url}" alt="${escapeHtml(img.name)}" />
    <div class="sidebar-info">
      <div class="sidebar-name">${escapeHtml(img.name)}</div>
      ${statusHtml}
    </div>
    <button class="sidebar-remove" title="Remove">✕</button>
  `;

  div.addEventListener("click",    ()  => setActive(img.id));
  div.querySelector(".sidebar-remove").addEventListener("click", (e) => {
    e.stopPropagation();
    removeImage(img.id);
  });

  return div;
}

/* ═══════════════════════════════════════
   RENDER — VIEWER
═══════════════════════════════════════ */

function renderViewer() {
  const img      = state.images.find((i) => i.id === state.activeId);
  const res      = state.activeId ? state.results[state.activeId]   : null;
  const isLoad   = state.activeId ? state.analyzing[state.activeId] : false;

  if (!img) {
    el.viewerFilename.textContent = "";
    el.confidenceMeta.textContent = "";
    el.previewImg.src = "";
    hide(el.classifBadge);
    hide(el.scanOverlay);
    return;
  }

  el.viewerFilename.textContent = `/ ${img.name}`;
  el.previewImg.src = img.url;
  el.previewImg.classList.remove("faulty", "ok");
  el.classifBadge.classList.remove("faulty", "ok");

  if (res?.classification) {
    const f = res.classification === "FAULTY";
    el.previewImg.classList.add(f ? "faulty" : "ok");
    el.classifBadge.textContent = res.classification;
    el.classifBadge.className   = f ? "faulty" : "ok";
    el.classifBadge.classList.remove("hidden");
    el.confidenceMeta.textContent = `CONFIDENCE: ${res.confidence}%`;
  } else {
    hide(el.classifBadge);
    el.confidenceMeta.textContent = "";
  }

  isLoad ? show(el.scanOverlay) : hide(el.scanOverlay);
}

/* ═══════════════════════════════════════
   RENDER — RESULTS
═══════════════════════════════════════ */

function renderResults() {
  const res    = state.activeId ? state.results[state.activeId]   : null;
  const isLoad = state.activeId ? state.analyzing[state.activeId] : false;

  hide(el.resPlaceholder);
  hide(el.resLoading);
  hide(el.resError);
  hide(el.resContent);

  if (!state.activeId) { show(el.resPlaceholder); return; }
  if (isLoad)          { show(el.resLoading);      return; }
  if (!res)            { show(el.resPlaceholder);  return; }

  if (res.error) {
    el.resError.textContent = `✕ ${res.error}`;
    show(el.resError);
    return;
  }

  const isFaulty = res.classification === "FAULTY";

  el.resClassBlock.className = `classification-block ${isFaulty ? "faulty" : "ok"}`;
  el.resClassVal.textContent = res.classification;
  el.resClassVal.className   = `classification-value ${isFaulty ? "faulty" : "ok"}`;

  el.resConfPct.textContent  = `${res.confidence}%`;
  el.resConfPct.className    = `confidence-pct ${isFaulty ? "faulty" : "ok"}`;
  el.resConfFill.className   = `confidence-fill ${isFaulty ? "faulty" : "ok"}`;
  el.resConfFill.style.width = "0%";
  requestAnimationFrame(() => setTimeout(() => { el.resConfFill.style.width = `${res.confidence}%`; }, 50));

  el.resSummary.textContent   = res.summary || "";
  el.resRecommend.textContent = res.recommendation || "";

  if (res.defects?.length > 0) {
    el.resDefectCount.textContent = res.defects.length;
    el.resDefectsList.innerHTML   = res.defects.map(buildDefectCard).join("");
    show(el.resDefectsWrap);
  } else {
    hide(el.resDefectsWrap);
  }

  show(el.resContent);
}

function buildDefectCard(d) {
  const sev = d.severity || "LOW";
  return `
    <div class="defect-card sev-${sev}">
      <div class="defect-card-header">
        <span class="defect-type">${escapeHtml(d.type)}</span>
        <span class="defect-severity badge-${sev}">${sev}</span>
      </div>
      <div class="defect-location">📍 ${escapeHtml(d.location)}</div>
      <div class="defect-desc">${escapeHtml(d.description)}</div>
    </div>
  `;
}

/* ═══════════════════════════════════════
   HELPERS
═══════════════════════════════════════ */

function show(e) { e.classList.remove("hidden"); }
function hide(e) { e.classList.add("hidden"); }

function updateDropZoneVisibility() {
  if (state.images.length > 0) { hide(el.dropZone); show(el.workspace); }
  else                          { show(el.dropZone); hide(el.workspace); }
}

function updateHeaderQueue() {
  el.queueCount.textContent = Object.values(state.analyzing).filter(Boolean).length;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/* ═══════════════════════════════════════
   INIT
═══════════════════════════════════════ */

initAuth();
