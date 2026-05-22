const NAME = "RÉMI DubzVX";
const el   = document.getElementById("typed-name");

function typeWriter(text, node, delay) {
  let i = 0;
  node.innerHTML = '<span class="cursor">█</span>';
  const iv = setInterval(() => {
    if (i < text.length) {
      node.innerHTML = text.slice(0, i + 1) + '<span class="cursor">█</span>';
      i++;
    } else clearInterval(iv);
  }, delay || 80);
}

window.addEventListener("load", () => setTimeout(() => typeWriter(NAME, el, 90), 400));

const LINES = [
  { t: "$ initializing threat_scan.sh...",           d: 0,    type: "cmd"  },
  { t: "$ loading MITRE ATT&CK framework...",        d: 600,  type: "cmd"  },
  { t: "[OK] 185 techniques loaded — 14 tactics",    d: 1000, type: "ok"   },
  { t: "$ connecting to Splunk Enterprise...",       d: 1500, type: "cmd"  },
  { t: "[OK] Splunk ES — 12 data sources active",    d: 1900, type: "ok"   },
  { t: "$ querying SentinelOne Deep Visibility...",  d: 2400, type: "cmd"  },
  { t: "[!!] Suspicious process injection — WS-042", d: 2900, type: "warn" },
  { t: "[!!] LSASS memory access detected",          d: 3200, type: "warn" },
  { t: "$ correlating IOCs with threat feeds...",    d: 3700, type: "cmd"  },
  { t: "[OK] APT29 TTP signature matched",           d: 4100, type: "ok"   },
  { t: "$ hunt hypothesis confirmed.",               d: 4600, type: "ok"   },
  { t: "$ generating Sigma rule...",                 d: 5000, type: "cmd"  },
  { t: "[OK] Rule deployed to Splunk.",           d: 5500, type: "ok"   },
  { t: "$ █",                                        d: 6000, type: "cursor"},
];

function buildTerminal() {
  const out = document.getElementById("terminal-output");
  if (!out) return;
  LINES.forEach(({ t, d, type }) => {
    setTimeout(() => {
      const p = document.createElement("p");
      p.className = "t-line";
      if (type === "cursor") p.innerHTML = `<span class="t-prompt">$</span> <span class="t-cursor">█</span>`;
      else if (type === "cmd")  p.innerHTML = `<span class="t-cmd">${t}</span>`;
      else if (type === "ok")   p.innerHTML = `<span style="color:#00ff88">${t}</span>`;
      else if (type === "warn") p.innerHTML = `<span style="color:#ffa500">${t}</span>`;
      out.appendChild(p);
      out.scrollTop = out.scrollHeight;
    }, d);
  });
}
window.addEventListener("load", buildTerminal);

// Scroll reveal
const items = document.querySelectorAll(".about-grid > *, .stat-item, .contact-solo");
items.forEach(el => el.classList.add("reveal"));
const obs = new IntersectionObserver(entries => {
  entries.forEach((e, i) => {
    if (e.isIntersecting) {
      setTimeout(() => e.target.classList.add("visible"), i * 80);
      obs.unobserve(e.target);
    }
  });
}, { threshold: 0.1 });
items.forEach(el => obs.observe(el));
