/**
 * VISIONCORE — Defect Analysis System
 * app.js — Invite-only auth via Netlify GoTrue API
 *
 * ┌─ Normal flow ─────────────────────────────────────────────┐
 * │  User visits site → Login screen → POST /token → enter app │
 * └───────────────────────────────────────────────────────────┘
 *
 * ┌─ First-time invite flow ──────────────────────────────────────────────────┐
 * │  Admin sends invite from Netlify Dashboard → Identity → Invite users      │
 * │  User clicks email link → lands on site with #invite_token=TOKEN in URL   │
 * │  App detects token → shows "Set Password" screen                          │
 * │  User sets password → POST /.netlify/identity/verify (type:invite)        │
 * │  App immediately logs in → enter app                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

"use strict";

/* ═══════════════════════════════════════
   STATE
═══════════════════════════════════════ */
const state = {
  accessToken:  null,
  refreshToken: null,
  userEmail:    null,
  images:       [],
  results:      {},
  analyzing:    {},
  activeId:     null,
};

/* ═══════════════════════════════════════
   DOM
═══════════════════════════════════════ */
const $  = (id) => document.getElementById(id);
const el = {
  // Auth
  loginGate:       $("login-gate"),
  authAlert:       $("auth-alert"),
  screenLogin:     $("screen-login"),
  screenInvite:    $("screen-invite"),
  // Login form
  loginEmail:      $("login-email"),
  loginPassword:   $("login-password"),
  loginSubmit:     $("login-submit"),
  // Invite form
  inviteEmail:     $("invite-email"),
  invitePassword:  $("invite-password"),
  inviteConfirm:   $("invite-confirm"),
  inviteSubmit:    $("invite-submit"),
  // App shell
  app:             $("app"),
  userInfo:        $("user-info"),
  logoutBtn:       $("logout-btn"),
  // Sidebar
  imageList:       $("image-list"),
  imageCount:      $("image-count"),
  queueCount:      $("queue-count"),
  addBtn:          $("add-btn"),
  fileInput:       $("file-input"),
  // Content
  dropZone:        $("drop-zone"),
  workspace:       $("workspace"),
  // Viewer
  viewerFilename:  $("viewer-filename"),
  confidenceMeta:  $("confidence-meta"),
  previewImg:      $("preview-img"),
  classifBadge:    $("classification-badge"),
  scanOverlay:     $("scan-overlay"),
  // Results
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
   GOTRUE API
═══════════════════════════════════════ */
const IDENTITY_URL = "/.netlify/identity";

/** Standard email + password login */
async function apiLogin(email, password) {
  const res = await fetch(`${IDENTITY_URL}/token`, {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    new URLSearchParams({ grant_type: "password", username: email, password }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error_description || data.msg || "Invalid email or password.");
  }
  return data; // { access_token, refresh_token, expires_in }
}

/**
 * Accept an invite token and set a password.
 * The invite_token acts as a short-lived JWT — we send it as the Bearer token
 * and PUT a new password onto the user account.
 */
async function apiAcceptInvite(inviteToken, password) {
  // Netlify invite tokens are short opaque strings (NOT JWTs).
  // Correct endpoint: POST /verify with type:"invite"
  // Returns a full session: { access_token, refresh_token, user: { email } }
  const res = await fetch(`${IDENTITY_URL}/verify`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ token: inviteToken, type: "invite", password }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.msg || data.error_description || "Failed to activate account. The invite link may have expired.");
  }
  return data;
}

/** Decode a JWT payload (no verification — client-side only) */
function decodeJwtPayload(token) {
  try {
    return JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return null;
  }
}

/** Refresh the access token silently */
async function apiRefreshToken(rt) {
  const res = await fetch(`${IDENTITY_URL}/token`, {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error("Session expired — please sign in again.");
  return data;
}

/** Return a valid access token, refreshing if near expiry */
async function getValidToken() {
  try {
    const payload = decodeJwtPayload(state.accessToken);
    if (payload && Date.now() < payload.exp * 1000 - 60_000) {
      return state.accessToken; // still fresh
    }
  } catch (_) { /* fall through to refresh */ }

  const data = await apiRefreshToken(state.refreshToken);
  state.accessToken  = data.access_token;
  state.refreshToken = data.refresh_token || state.refreshToken;
  saveSession();
  return state.accessToken;
}

/* ═══════════════════════════════════════
   SESSION  (sessionStorage)
═══════════════════════════════════════ */
function saveSession() {
  sessionStorage.setItem("vc_at", state.accessToken  || "");
  sessionStorage.setItem("vc_rt", state.refreshToken || "");
  sessionStorage.setItem("vc_em", state.userEmail    || "");
}
function loadSession() {
  state.accessToken  = sessionStorage.getItem("vc_at") || null;
  state.refreshToken = sessionStorage.getItem("vc_rt") || null;
  state.userEmail    = sessionStorage.getItem("vc_em") || null;
}
function clearSession() {
  ["vc_at","vc_rt","vc_em"].forEach((k) => sessionStorage.removeItem(k));
  state.accessToken = state.refreshToken = state.userEmail = null;
}

/* ═══════════════════════════════════════
   AUTH UI HELPERS
═══════════════════════════════════════ */
function showAlert(msg, type = "error") {
  el.authAlert.innerHTML = msg;
  el.authAlert.className = `auth-alert auth-alert--${type}`;
}
function clearAlert() {
  el.authAlert.className   = "auth-alert hidden";
  el.authAlert.textContent = "";
}
function setLoading(btn, loading) {
  btn.disabled = loading;
  btn.querySelector(".btn-label").classList.toggle("hidden",  loading);
  btn.querySelector(".btn-spinner").classList.toggle("hidden", !loading);
}

/* Enter-key support */
el.loginPassword.addEventListener("keydown", (e) => e.key === "Enter" && el.loginSubmit.click());
el.inviteConfirm.addEventListener("keydown", (e) => e.key === "Enter" && el.inviteSubmit.click());

/* ─── LOGIN SUBMIT ─── */
el.loginSubmit.addEventListener("click", async () => {
  clearAlert();
  const email    = el.loginEmail.value.trim();
  const password = el.loginPassword.value;
  if (!email || !password) { showAlert("Please enter your email and password."); return; }

  setLoading(el.loginSubmit, true);
  try {
    const data         = await apiLogin(email, password);
    state.accessToken  = data.access_token;
    state.refreshToken = data.refresh_token;
    state.userEmail    = email;
    saveSession();
    enterApp();
  } catch (err) {
    showAlert(err.message);
  } finally {
    setLoading(el.loginSubmit, false);
  }
});

/* ─── ACCEPT INVITE SUBMIT ─── */
el.inviteSubmit.addEventListener("click", async () => {
  clearAlert();
  const password = el.invitePassword.value;
  const confirm  = el.inviteConfirm.value;
  const token    = el.inviteSubmit.dataset.inviteToken;

  if (!password)              { showAlert("Please choose a password."); return; }
  if (password.length < 8)   { showAlert("Password must be at least 8 characters."); return; }
  if (password !== confirm)   { showAlert("Passwords do not match."); return; }

  setLoading(el.inviteSubmit, true);
  try {
    // Step 1 — Verify invite token + set password in one call
    // Response includes access_token, refresh_token AND user.email directly
    const session = await apiAcceptInvite(token, password);

    // Step 2 — Clear the invite token from the URL (clean up hash)
    history.replaceState(null, "", window.location.pathname);

    // Step 3 — Store session and enter app (no second login needed)
    state.accessToken  = session.access_token;
    state.refreshToken = session.refresh_token;
    state.userEmail    = session.user?.email || "";
    saveSession();
    enterApp();

  } catch (err) {
    showAlert(err.message);
  } finally {
    setLoading(el.inviteSubmit, false);
  }
});

/* ─── LOGOUT ─── */
el.logoutBtn.addEventListener("click", () => {
  clearSession();
  state.images.forEach((img) => URL.revokeObjectURL(img.url));
  Object.assign(state, { images: [], results: {}, analyzing: {}, activeId: null });
  show(el.loginGate);
  hide(el.app);
  updateDropZoneVisibility();
});

function enterApp() {
  hide(el.loginGate);
  show(el.app);
  el.userInfo.textContent = state.userEmail || "";
  updateDropZoneVisibility();
  renderSidebar();
}

/* ═══════════════════════════════════════
   BOOT — check URL for invite token, else restore session
═══════════════════════════════════════ */
(function boot() {
  // Parse URL hash: #invite_token=XXX  (Netlify appends this to the invite link)
  const hash        = window.location.hash.slice(1); // strip leading #
  const params      = new URLSearchParams(hash);
  const inviteToken = params.get("invite_token");

  if (inviteToken) {
    // ── Show the invite acceptance screen
    hide(el.screenLogin);
    show(el.screenInvite);

    // Netlify invite tokens are opaque strings, not JWTs — cannot decode email.
    // Email will be populated from the API response after activation.
    el.inviteEmail.placeholder = "Will be confirmed on activation";

    // Store token on the submit button for use in click handler
    el.inviteSubmit.dataset.inviteToken = inviteToken;
    return; // don't check for an existing session
  }

  // ── No invite token — try to restore a previous session
  loadSession();
  if (state.accessToken && state.refreshToken) {
    apiRefreshToken(state.refreshToken)
      .then((data) => {
        state.accessToken  = data.access_token;
        state.refreshToken = data.refresh_token || state.refreshToken;
        saveSession();
        enterApp();
      })
      .catch(() => clearSession()); // session invalid, stay on login screen
  }
})();

/* ═══════════════════════════════════════
   FILE HANDLING
═══════════════════════════════════════ */
el.addBtn.addEventListener("click",   () => el.fileInput.click());
el.dropZone.addEventListener("click", () => el.fileInput.click());

el.fileInput.addEventListener("change", (e) => { addImages(e.target.files); e.target.value = ""; });

el.dropZone.addEventListener("dragover",  (e) => { e.preventDefault(); el.dropZone.classList.add("drag-over"); });
el.dropZone.addEventListener("dragleave", ()  => el.dropZone.classList.remove("drag-over"));
el.dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  el.dropZone.classList.remove("drag-over");
  addImages(e.dataTransfer.files);
});

document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop",     (e) => {
  e.preventDefault();
  if (state.accessToken) addImages(e.dataTransfer.files);
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
   ANALYSIS
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
    const token       = await getValidToken();
    const imageBase64 = await toBase64(imgObj.file);
    const mediaType   = imgObj.file.type || "image/jpeg";

    const response = await fetch("/.netlify/functions/analyze", {
      method:  "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
      body:    JSON.stringify({ imageBase64, mediaType }),
    });

    const data = await response.json();
    if (!response.ok || data.error) throw new Error(data.error || `HTTP ${response.status}`);
    state.results[imgObj.id] = data;

  } catch (err) {
    state.results[imgObj.id] = { error: `Analysis failed: ${err.message}` };
  }

  state.analyzing[imgObj.id] = false;
  updateHeaderQueue();
  renderSidebarItem(imgObj.id);
  if (state.activeId === imgObj.id) { renderViewer(); renderResults(); }
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
  if (existing) existing.replaceWith(buildSidebarItem(img));
}

function buildSidebarItem(img) {
  const res      = state.results[img.id];
  const isActive = state.activeId === img.id;
  const isLoad   = state.analyzing[img.id];
  const div      = document.createElement("div");
  div.className  = `sidebar-item${isActive ? " active" : ""}`;
  div.dataset.id = img.id;

  let statusHtml;
  if (isLoad)                 statusHtml = `<span class="sidebar-status status-scanning">⟳ Scanning...</span>`;
  else if (res?.classification) {
    const c = res.classification === "FAULTY" ? "faulty" : "ok";
    statusHtml = `<span class="sidebar-status status-${c}">● ${res.classification}</span>`;
  }
  else if (res?.error)        statusHtml = `<span class="sidebar-status status-error">✕ Error</span>`;
  else                        statusHtml = `<span class="sidebar-status status-scanning">— Pending</span>`;

  div.innerHTML = `
    <img class="sidebar-thumb" src="${img.url}" alt="${escapeHtml(img.name)}" />
    <div class="sidebar-info">
      <div class="sidebar-name">${escapeHtml(img.name)}</div>
      ${statusHtml}
    </div>
    <button class="sidebar-remove" title="Remove">✕</button>
  `;
  div.addEventListener("click", () => setActive(img.id));
  div.querySelector(".sidebar-remove").addEventListener("click", (e) => {
    e.stopPropagation(); removeImage(img.id);
  });
  return div;
}

/* ═══════════════════════════════════════
   RENDER — VIEWER
═══════════════════════════════════════ */
function renderViewer() {
  const img    = state.images.find((i) => i.id === state.activeId);
  const res    = state.activeId ? state.results[state.activeId]   : null;
  const isLoad = state.activeId ? state.analyzing[state.activeId] : false;

  if (!img) {
    el.viewerFilename.textContent = "";
    el.confidenceMeta.textContent = "";
    el.previewImg.src = "";
    hide(el.classifBadge); hide(el.scanOverlay);
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

  hide(el.resPlaceholder); hide(el.resLoading); hide(el.resError); hide(el.resContent);

  if (!state.activeId)  { show(el.resPlaceholder); return; }
  if (isLoad)           { show(el.resLoading);      return; }
  if (!res)             { show(el.resPlaceholder);  return; }
  if (res.error)        { el.resError.textContent = `✕ ${res.error}`; show(el.resError); return; }

  const isFaulty = res.classification === "FAULTY";

  el.resClassBlock.className = `classification-block ${isFaulty ? "faulty" : "ok"}`;
  el.resClassVal.textContent = res.classification;
  el.resClassVal.className   = `classification-value ${isFaulty ? "faulty" : "ok"}`;
  el.resConfPct.textContent  = `${res.confidence}%`;
  el.resConfPct.className    = `confidence-pct ${isFaulty ? "faulty" : "ok"}`;
  el.resConfFill.className   = `confidence-fill ${isFaulty ? "faulty" : "ok"}`;
  el.resConfFill.style.width = "0%";
  requestAnimationFrame(() => setTimeout(() => { el.resConfFill.style.width = `${res.confidence}%`; }, 50));

  el.resSummary.textContent   = res.summary       || "";
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
    </div>`;
}

/* ═══════════════════════════════════════
   HELPERS
═══════════════════════════════════════ */
function show(e)  { e.classList.remove("hidden"); }
function hide(e)  { e.classList.add("hidden"); }

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
