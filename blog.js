const ARTICLES_INDEX = "articles/articles.json";
let allArticles = [];

async function loadArticles() {
  const grid    = document.getElementById("articles-grid");
  const loading = document.getElementById("loading-state");
  try {
    const res   = await fetch(ARTICLES_INDEX);
    allArticles = await res.json();
    loading.remove();
    renderArticles(allArticles);
  } catch {
    loading.innerHTML = `<span class="font-mono" style="color:var(--red)">[ERR] Failed to load articles/articles.json</span>`;
  }
}

function categoryLabel(cat) {
  return { writeup: "WRITE-UP", detection: "DETECTION", malware: "MALWARE" }[cat] || cat.toUpperCase();
}

function formatDate(d) {
  return new Date(d).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

function renderArticles(articles) {
  const grid = document.getElementById("articles-grid");
  grid.innerHTML = "";

  if (!articles.length) {
    grid.innerHTML = `
      <div class="no-results">
        <span>[404]</span>
        No articles found.
      </div>`;
    return;
  }

  articles.forEach((a, i) => {
    const card = document.createElement("a");
    card.className = "article-card reveal";
    card.href = `article.html?slug=${a.slug}`;
    card.dataset.category = a.category;
    card.setAttribute("aria-label", `Read: ${a.title}`);
    card.innerHTML = `
      <div class="ac-header">
        <span class="ac-cat ${a.category}">${categoryLabel(a.category)}</span>
        <span class="ac-date">${formatDate(a.date)}</span>
      </div>
      <h2 class="ac-title">${a.title}</h2>
      <p class="ac-excerpt">${a.excerpt}</p>
      <div class="ac-tags">${(a.tags||[]).map(t=>`<span class="ac-tag">${t}</span>`).join("")}</div>
      <div class="ac-footer">
        <span class="ac-meta">⏱ ${a.readtime||"5 min"}</span>
        <span class="ac-read">READ →</span>
      </div>`;
    grid.appendChild(card);
    setTimeout(() => card.classList.add("visible"), i * 60);
  });
}

document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    applyFilters();
  });
});

document.getElementById("blog-search").addEventListener("input", applyFilters);

function applyFilters() {
  const cat   = document.querySelector(".filter-btn.active").dataset.filter;
  const query = document.getElementById("blog-search").value.toLowerCase().trim();
  renderArticles(allArticles.filter(a => {
    const matchCat = cat === "all" || a.category === cat;
    const matchQ   = !query || a.title.toLowerCase().includes(query) || a.excerpt.toLowerCase().includes(query) || (a.tags||[]).some(t=>t.toLowerCase().includes(query));
    return matchCat && matchQ;
  }));
}

loadArticles();
