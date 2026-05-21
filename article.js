/* =============================================
   ARTICLE.JS — Markdown reader with ToC & hljs
   ============================================= */

// ── HELPERS ───────────────────────────────────
function getSlug() {
  const params = new URLSearchParams(window.location.search);
  return params.get("slug");
}

function formatDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "long", year: "numeric" });
}

function categoryLabel(cat) {
  return { writeup: "WRITE-UP", detection: "DÉTECTION", malware: "MALWARE" }[cat] || cat.toUpperCase();
}

function slugify(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

function estimateReadTime(text) {
  const words = text.split(/\s+/).length;
  const mins  = Math.max(1, Math.round(words / 200));
  return `${mins} min de lecture`;
}

// ── LOAD ARTICLE ──────────────────────────────
async function loadArticle() {
  const slug = getSlug();
  if (!slug) { showError("Aucun article spécifié."); return; }

  // Load index to get metadata
  let meta;
  try {
    const res  = await fetch("articles/index.json");
    const all  = await res.json();
    meta = all.find(a => a.slug === slug);
  } catch {
    showError("Impossible de charger l'index des articles.");
    return;
  }

  if (!meta) { showError(`Article "${slug}" introuvable.`); return; }

  // Load Markdown file
  let markdown;
  try {
    const res = await fetch(`articles/${slug}.md`);
    if (!res.ok) throw new Error(res.status);
    markdown = await res.text();
  } catch {
    showError(`Fichier articles/${slug}.md introuvable.`);
    return;
  }

  // Set page title
  document.title = `ThreatHunter // ${meta.title}`;

  // Render header
  renderHeader(meta, markdown);

  // Render body
  renderBody(markdown);

  // Build ToC from rendered headings
  buildToC();

  // Syntax highlight
  hljs.highlightAll();

  // Add copy buttons to code blocks
  addCopyButtons();

  // Render prev/next nav
  renderNav(slug);
}

// ── RENDER HEADER ─────────────────────────────
function renderHeader(meta, markdown) {
  const el = document.getElementById("article-header");

  const tagsHtml = (meta.tags || []).map(t => `<span class="ah-tag">${t}</span>`).join("");
  const tldrHtml = meta.tldr
    ? `<div class="ah-tldr"><strong>// TL;DR</strong>${meta.tldr}</div>`
    : "";

  el.innerHTML = `
    <div class="ah-meta">
      <span class="ah-cat ${meta.category}">${categoryLabel(meta.category)}</span>
      <span class="ah-date">${formatDate(meta.date)}</span>
      <span class="ah-dot">·</span>
      <span class="ah-readtime">${meta.readtime || estimateReadTime(markdown)}</span>
    </div>
    <h1 class="ah-title">${meta.title}</h1>
    ${tldrHtml}
    <div class="ah-tags">${tagsHtml}</div>
  `;
}

// ── RENDER BODY ───────────────────────────────
function renderBody(markdown) {
  const el = document.getElementById("article-body");

  // Configure marked
  marked.setOptions({
    breaks: true,
    gfm: true,
  });

  // Custom renderer: add IDs to headings for ToC anchors
  const renderer = new marked.Renderer();
  renderer.heading = (text, level) => {
    const id = slugify(text);
    return `<h${level} id="${id}">${text}</h${level}>`;
  };

  el.innerHTML = marked.parse(markdown, { renderer });
}

// ── BUILD TOC ─────────────────────────────────
function buildToC() {
  const body    = document.getElementById("article-body");
  const tocEl   = document.getElementById("article-toc");
  const headings = body.querySelectorAll("h2, h3");

  if (headings.length < 2) { tocEl.style.display = "none"; return; }

  const items = Array.from(headings).map(h => ({
    text: h.textContent,
    id:   h.id,
    level: h.tagName,
  }));

  const listItems = items.map(item => {
    const cls = item.level === "H3" ? " class=\"toc-h3\"" : "";
    return `<li><a href="#${item.id}"${cls}>${item.text}</a></li>`;
  }).join("");

  tocEl.innerHTML = `
    <p class="toc-title">// TABLE DES MATIÈRES</p>
    <ul class="toc-list">${listItems}</ul>
  `;
}

// ── COPY BUTTONS ──────────────────────────────
function addCopyButtons() {
  document.querySelectorAll(".article-body pre").forEach(pre => {
    pre.style.position = "relative";
    const btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "COPIER";
    btn.addEventListener("click", () => {
      const code = pre.querySelector("code")?.textContent || "";
      navigator.clipboard.writeText(code).then(() => {
        btn.textContent = "✓ COPIÉ";
        setTimeout(() => { btn.textContent = "COPIER"; }, 1800);
      });
    });
    pre.appendChild(btn);
  });
}

// ── PREV / NEXT NAV ───────────────────────────
async function renderNav(currentSlug) {
  const navEl = document.getElementById("article-nav");
  try {
    const res  = await fetch("articles/index.json");
    const all  = await res.json();
    const idx  = all.findIndex(a => a.slug === currentSlug);

    const prev = idx > 0 ? all[idx - 1] : null;
    const next = idx < all.length - 1 ? all[idx + 1] : null;

    let html = "";
    if (prev) {
      html += `<a href="article.html?slug=${prev.slug}">
        <span class="an-dir">← PRÉCÉDENT</span>
        <span class="an-title">${prev.title}</span>
      </a>`;
    } else {
      html += `<div></div>`;
    }
    if (next) {
      html += `<a href="article.html?slug=${next.slug}" style="text-align:right">
        <span class="an-dir">SUIVANT →</span>
        <span class="an-title">${next.title}</span>
      </a>`;
    } else {
      html += `<div></div>`;
    }
    navEl.innerHTML = html;
  } catch { navEl.style.display = "none"; }
}

// ── ERROR ─────────────────────────────────────
function showError(msg) {
  document.getElementById("article-header").innerHTML =
    `<p class="font-mono" style="color:var(--red)">[ERR] ${msg}</p>`;
}

// ── INIT ──────────────────────────────────────
loadArticle();
