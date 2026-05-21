/* =============================================
   BLOG.JS — Article listing, filter, search
   ============================================= */

const ARTICLES_INDEX = "articles/index.json";

let allArticles = [];

// ── LOAD ARTICLES ─────────────────────────────
async function loadArticles() {
  const grid    = document.getElementById("articles-grid");
  const loading = document.getElementById("loading-state");

  try {
    const res  = await fetch(ARTICLES_INDEX);
    allArticles = await res.json();
    loading.remove();
    renderArticles(allArticles);
  } catch (err) {
    loading.innerHTML = `
      <span class="font-mono" style="color:var(--red)">
        [ERR] Impossible de charger articles/index.json<br>
        <span style="color:var(--text-muted);font-size:0.75rem">Vérifiez que le fichier existe dans votre dépôt.</span>
      </span>`;
  }
}

// ── RENDER ────────────────────────────────────
function renderArticles(articles) {
  const grid = document.getElementById("articles-grid");
  grid.innerHTML = "";

  if (articles.length === 0) {
    grid.innerHTML = `
      <div class="no-results">
        <span>[404]</span>
        Aucun article trouvé pour cette recherche.
      </div>`;
    return;
  }

  articles.forEach((a, i) => {
    const card = document.createElement("a");
    card.className = "article-card reveal";
    card.href = `article.html?slug=${a.slug}`;
    card.dataset.category = a.category;
    card.setAttribute("aria-label", `Lire : ${a.title}`);

    const tagsHtml = (a.tags || [])
      .map(t => `<span class="ac-tag">${t}</span>`)
      .join("");

    card.innerHTML = `
      <div class="ac-header">
        <span class="ac-cat ${a.category}">${categoryLabel(a.category)}</span>
        <span class="ac-date">${formatDate(a.date)}</span>
      </div>
      <h2 class="ac-title">${a.title}</h2>
      <p class="ac-excerpt">${a.excerpt}</p>
      <div class="ac-tags">${tagsHtml}</div>
      <div class="ac-footer">
        <div class="ac-meta">
          <span>⏱ ${a.readtime || "5 min"}</span>
        </div>
        <span class="ac-read">LIRE →</span>
      </div>`;

    grid.appendChild(card);

    // Staggered reveal
    setTimeout(() => card.classList.add("visible"), i * 60);
  });
}

function categoryLabel(cat) {
  return { writeup: "WRITE-UP", detection: "DÉTECTION", malware: "MALWARE" }[cat] || cat.toUpperCase();
}

function formatDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
}

// ── FILTER ────────────────────────────────────
document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    applyFilters();
  });
});

// ── SEARCH ────────────────────────────────────
const searchInput = document.getElementById("blog-search");
searchInput.addEventListener("input", applyFilters);

function applyFilters() {
  const cat   = document.querySelector(".filter-btn.active").dataset.filter;
  const query = searchInput.value.toLowerCase().trim();

  const filtered = allArticles.filter(a => {
    const matchCat = cat === "all" || a.category === cat;
    const matchQ   = !query ||
      a.title.toLowerCase().includes(query) ||
      a.excerpt.toLowerCase().includes(query) ||
      (a.tags || []).some(t => t.toLowerCase().includes(query));
    return matchCat && matchQ;
  });

  renderArticles(filtered);
}

// ── INIT ──────────────────────────────────────
loadArticles();
