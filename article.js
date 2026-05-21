function getSlug() { return new URLSearchParams(window.location.search).get("slug"); }
function formatDate(d) { return new Date(d).toLocaleDateString("en-GB", { day:"2-digit", month:"long", year:"numeric" }); }
function categoryLabel(cat) { return { writeup:"WRITE-UP", detection:"DETECTION", malware:"MALWARE" }[cat] || cat.toUpperCase(); }
function slugify(t) { return t.toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,""); }
function readTime(text) { return `${Math.max(1,Math.round(text.split(/\s+/).length/200))} min read`; }

async function loadArticle() {
  const slug = getSlug();
  if (!slug) { showError("No article specified."); return; }

  let meta;
  try {
    const res = await fetch("articles/articles.json");
    const all = await res.json();
    meta = all.find(a => a.slug === slug);
  } catch { showError("Failed to load article index."); return; }
  if (!meta) { showError(`Article "${slug}" not found.`); return; }

  let markdown;
  try {
    const res = await fetch(`articles/${slug}.md`);
    if (!res.ok) throw new Error();
    markdown = await res.text();
  } catch { showError(`File articles/${slug}.md not found.`); return; }

  document.title = `DubzVX // ${meta.title}`;
  renderHeader(meta, markdown);
  renderBody(markdown);
  buildToC();
  hljs.highlightAll();
  addCopyButtons();
  renderNav(slug);
}

function renderHeader(meta, markdown) {
  document.getElementById("article-header").innerHTML = `
    <div class="ah-meta">
      <span class="ah-cat ${meta.category}">${categoryLabel(meta.category)}</span>
      <span class="ah-date">${formatDate(meta.date)}</span>
      <span class="ah-dot">·</span>
      <span class="ah-readtime">${meta.readtime || readTime(markdown)}</span>
    </div>
    <h1 class="ah-title">${meta.title}</h1>
    ${meta.tldr ? `<div class="ah-tldr"><strong>// TL;DR</strong>${meta.tldr}</div>` : ""}
    <div class="ah-tags">${(meta.tags||[]).map(t=>`<span class="ah-tag">${t}</span>`).join("")}</div>`;
}

function renderBody(markdown) {
  const renderer = new marked.Renderer();
  renderer.heading = (text, level) => `<h${level} id="${slugify(text)}">${text}</h${level}>`;
  document.getElementById("article-body").innerHTML = marked.parse(markdown, { renderer, breaks: true, gfm: true });
}

function buildToC() {
  const headings = document.getElementById("article-body").querySelectorAll("h2, h3");
  const tocEl    = document.getElementById("article-toc");
  if (headings.length < 2) { tocEl.style.display = "none"; return; }
  tocEl.innerHTML = `<p class="toc-title">// TABLE OF CONTENTS</p>
    <ul class="toc-list">${Array.from(headings).map(h =>
      `<li><a href="#${h.id}" ${h.tagName==="H3"?'class="toc-h3"':''}>${h.textContent}</a></li>`
    ).join("")}</ul>`;
}

function addCopyButtons() {
  document.querySelectorAll(".article-body pre").forEach(pre => {
    pre.style.position = "relative";
    const btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "COPY";
    btn.onclick = () => {
      navigator.clipboard.writeText(pre.querySelector("code")?.textContent || "");
      btn.textContent = "✓ COPIED";
      setTimeout(() => btn.textContent = "COPY", 1800);
    };
    pre.appendChild(btn);
  });
}

async function renderNav(currentSlug) {
  try {
    const all = await (await fetch("articles/articles.json")).json();
    const idx  = all.findIndex(a => a.slug === currentSlug);
    const prev = idx > 0 ? all[idx-1] : null;
    const next = idx < all.length-1 ? all[idx+1] : null;
    document.getElementById("article-nav").innerHTML =
      (prev ? `<a href="article.html?slug=${prev.slug}"><span class="an-dir">← PREVIOUS</span><span class="an-title">${prev.title}</span></a>` : "<div></div>") +
      (next ? `<a href="article.html?slug=${next.slug}" style="text-align:right"><span class="an-dir">NEXT →</span><span class="an-title">${next.title}</span></a>` : "<div></div>");
  } catch { document.getElementById("article-nav").style.display = "none"; }
}

function showError(msg) {
  document.getElementById("article-header").innerHTML = `<p class="font-mono" style="color:var(--red)">[ERR] ${msg}</p>`;
}

loadArticle();
