/* =============================================
   THREAT HUNTER PORTFOLIO — MAIN JS
   ============================================= */

// ── TYPING EFFECT (hero name) ───────────────────
const NAME = "VOTRE NOM";
const el   = document.getElementById("typed-name");

function typeWriter(text, node, delay = 80) {
  let i = 0;
  node.innerHTML = '<span class="cursor">█</span>';
  const interval = setInterval(() => {
    if (i < text.length) {
      node.innerHTML = text.slice(0, i + 1) + '<span class="cursor">█</span>';
      i++;
    } else {
      clearInterval(interval);
    }
  }, delay);
}

window.addEventListener("load", () => {
  setTimeout(() => typeWriter(NAME, el, 90), 400);
});

// ── TERMINAL ANIMATION ────────────────────────
const TERMINAL_LINES = [
  { text: "$ initializing threat_scan.sh...", delay: 0,    type: "cmd" },
  { text: "$ loading MITRE ATT&CK framework...", delay: 600,  type: "cmd" },
  { text: "[OK] Loaded 185 techniques, 14 tactics", delay: 1000, type: "ok" },
  { text: "$ connecting to threat intel feeds...", delay: 1500, type: "cmd" },
  { text: "[OK] MISP / OTX / VirusTotal ready", delay: 1900, type: "ok" },
  { text: "$ scanning environment...", delay: 2400, type: "cmd" },
  { text: "[!!] Suspicious WMI activity detected", delay: 2900, type: "warn" },
  { text: "[!!] Possible lateral movement: DCOM", delay: 3200, type: "warn" },
  { text: "$ correlating IOCs...", delay: 3700, type: "cmd" },
  { text: "[OK] APT29 TTP signature matched", delay: 4100, type: "ok" },
  { text: "$ hunt hypothesis confirmed.", delay: 4600, type: "ok" },
  { text: "$ generating detection rule (Sigma)...", delay: 5000, type: "cmd" },
  { text: "[OK] Rule exported → sigma/apt29_wmi.yml", delay: 5500, type: "ok" },
  { text: "$ █", delay: 6000, type: "cursor" },
];

function buildTerminal() {
  const out = document.getElementById("terminal-output");
  if (!out) return;

  TERMINAL_LINES.forEach(({ text, delay, type }) => {
    setTimeout(() => {
      const line = document.createElement("p");
      line.className = "t-line";

      if (type === "cursor") {
        line.innerHTML = `<span class="t-prompt">$</span> <span class="t-cursor">█</span>`;
      } else if (type === "cmd") {
        line.innerHTML = `<span class="t-cmd">${text}</span>`;
        line.style.color = "#d4e4f0";
      } else if (type === "ok") {
        line.innerHTML = `<span style="color:#00ff88">${text}</span>`;
      } else if (type === "warn") {
        line.innerHTML = `<span style="color:#ffa500">${text}</span>`;
      }

      out.appendChild(line);
      out.scrollTop = out.scrollHeight;
    }, delay);
  });
}

window.addEventListener("load", buildTerminal);

// ── PROJECT FILTER ────────────────────────────
const filterBtns = document.querySelectorAll(".filter-btn");
const cards      = document.querySelectorAll(".project-card");

filterBtns.forEach(btn => {
  btn.addEventListener("click", () => {
    filterBtns.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");

    const filter = btn.dataset.filter;
    cards.forEach(card => {
      if (filter === "all" || card.dataset.category === filter) {
        card.classList.remove("hidden");
      } else {
        card.classList.add("hidden");
      }
    });
  });
});

// ── SCROLL REVEAL ─────────────────────────────
const revealItems = document.querySelectorAll(
  ".project-card, .skill-category, .stat-item, .about-grid > *, .contact-grid > *"
);

revealItems.forEach(el => el.classList.add("reveal"));

const observer = new IntersectionObserver(
  entries => {
    entries.forEach((entry, i) => {
      if (entry.isIntersecting) {
        setTimeout(() => entry.target.classList.add("visible"), i * 80);
        observer.unobserve(entry.target);
      }
    });
  },
  { threshold: 0.1, rootMargin: "0px 0px -40px 0px" }
);

revealItems.forEach(el => observer.observe(el));

// ── ACTIVE NAV LINK ───────────────────────────
const sections = document.querySelectorAll("section[id], header[id]");
const navLinks = document.querySelectorAll(".nav-links a");

const navObserver = new IntersectionObserver(
  entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        navLinks.forEach(link => {
          link.style.color = "";
          if (link.getAttribute("href") === "#" + entry.target.id) {
            link.style.color = "var(--green)";
          }
        });
      }
    });
  },
  { threshold: 0.4 }
);

sections.forEach(s => navObserver.observe(s));
