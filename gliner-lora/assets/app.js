const state = {
  raw: null,
  currentCase: null,
};

function normalizeWhitespace(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

async function init() {
  const response = await fetch("data/demo.json");
  const data = await response.json();
  state.raw = data;

  renderHero(data);
  renderComparison(data.model_comparison || []);
  renderExamples(data.cases || []);
  renderPolicy(data.policy || {});
  renderCategories(data.categories || []);

  const firstCase = data.cases?.[0] || null;
  if (firstCase) {
    document.getElementById("prompt-input").value = firstCase.prompt;
    renderCase(firstCase);
  }

  document.getElementById("run-check").addEventListener("click", runLookup);
}

function runLookup() {
  const prompt = normalizeWhitespace(document.getElementById("prompt-input").value);
  const match = (state.raw?.cases || []).find((item) => item.normalized_prompt === prompt);

  if (!match) {
    renderNotFound(prompt);
    return;
  }

  renderCase(match);
}

function renderHero(data) {
  document.getElementById("active-model").textContent = shortenPath(data.meta?.model_path || "unknown");
  document.getElementById("request-count").textContent = String(data.meta?.request_count || 0);
}

function renderComparison(rows) {
  const target = document.getElementById("comparison-grid");
  target.innerHTML = "";

  rows.forEach((row) => {
    const card = document.createElement("article");
    card.className = `comparison-card${row.label?.includes("v2") ? " is-primary" : ""}`;
    card.innerHTML = `
      <div class="card-head">
        <strong>${row.label}</strong>
        <span>threshold ${formatNumber(row.threshold, 2)}</span>
      </div>
      <div class="metric-grid">
        <div><span>precision</span><strong>${formatNumber(row.precision)}</strong></div>
        <div><span>recall</span><strong>${formatNumber(row.recall)}</strong></div>
        <div><span>F1</span><strong>${formatNumber(row.f1)}</strong></div>
      </div>
      <div class="footline">TP ${row.tp} · FP ${row.fp} · FN ${row.fn}</div>
    `;
    target.appendChild(card);
  });
}

function renderExamples(cases) {
  const target = document.getElementById("examples-grid");
  target.innerHTML = "";

  cases.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `example-card tone-${item.firewall?.decision || "neutral"}`;
    button.innerHTML = `
      <div class="card-head">
        <strong>${item.title}</strong>
        <span class="badge decision-${item.firewall?.decision || "warn"}">${item.firewall?.decision || item.interpretation?.status}</span>
      </div>
      <p>${item.prompt}</p>
      <small>${item.notes || ""}</small>
    `;
    button.addEventListener("click", () => {
      document.getElementById("prompt-input").value = item.prompt;
      renderCase(item);
    });
    target.appendChild(button);
  });
}

function renderPolicy(policy) {
  const target = document.getElementById("policy-grid");
  const rows = [
    ["Разрешенные транспорты", (policy.allowed_transports || []).join(", ")],
    ["Разрешенные клиенты", (policy.allowed_clients || []).join(", ")],
    ["Safe file roots", (policy.safe_file_roots || []).join(", ")],
    ["Blocked hosts", (policy.blocked_hosts || []).join(", ")],
    ["Blocked paths", (policy.blocked_paths || []).join(", ")],
    ["Warn / block thresholds", `${policy.warn_risk_threshold} / ${policy.block_risk_threshold}`],
  ];
  target.innerHTML = rows
    .map(
      ([label, value]) => `
        <div class="policy-line">
          <span>${label}</span>
          <strong>${value}</strong>
        </div>
      `
    )
    .join("");
}

function renderCategories(categories) {
  const target = document.getElementById("categories-grid");
  target.innerHTML = categories
    .map(
      (item) => `
        <article class="category-card">
          <strong>${item.name}</strong>
          <p>${item.description}</p>
        </article>
      `
    )
    .join("");
}

function renderCase(item) {
  state.currentCase = item;
  document.getElementById("not-found-card").classList.add("hidden");

  const interpretation = item.interpretation || {};
  const firewall = item.firewall || null;

  document.getElementById("interpretation-status").textContent = formatInterpretationStatus(interpretation.status);
  document.getElementById("interpretation-json").textContent = JSON.stringify(interpretation, null, 2);
  document.getElementById("mcp-request-json").textContent = JSON.stringify(item.mcp_request, null, 2);

  renderPromptSummary(item.prompt_analysis, item.prompt);
  renderFirewallSummary(firewall);
  renderRuleMatches(firewall?.rule_matches || []);
  renderFirewallSpans(firewall?.privacy_assessment?.spans || []);
}

function renderNotFound(prompt) {
  document.getElementById("interpretation-status").textContent = "не экспортирован";
  document.getElementById("interpretation-json").textContent = JSON.stringify(
    {
      status: "not_exported",
      prompt,
      message: "Для этого текста нет предрассчитанного результата в static JSON.",
    },
    null,
    2
  );
  document.getElementById("mcp-request-json").textContent = "null";
  renderPromptSummary(null, prompt);
  renderFirewallSummary(null);
  renderRuleMatches([]);
  renderFirewallSpans([]);

  const target = document.getElementById("not-found-card");
  target.classList.remove("hidden");
  target.innerHTML = `
    <strong>Этот запрос ещё не экспортирован</strong>
    <p>Добавь его в файл со списком demo-запросов и перегенерируй JSON:</p>
    <pre>${state.raw?.meta?.update_command || ""}</pre>
    <p class="footline">Файл запросов: ${state.raw?.meta?.requests_file || ""}</p>
  `;
}

function renderPromptSummary(analysis, prompt) {
  const summary = document.getElementById("prompt-summary");
  const spansTarget = document.getElementById("prompt-spans");

  if (!analysis) {
    summary.innerHTML = `
      <article class="summary-card"><span>Prompt</span><strong>${escapeHtml(prompt || "—")}</strong></article>
      <article class="summary-card"><span>GLiNER span count</span><strong>0</strong></article>
      <article class="summary-card"><span>Комментарий</span><strong>Нет предрассчитанного анализа</strong></article>
    `;
    spansTarget.innerHTML = `<p class="empty-state">Сначала добавь prompt в экспортный JSON и перегенерируй demo payload.</p>`;
    return;
  }

  summary.innerHTML = `
    <article class="summary-card">
      <span>Prompt</span>
      <strong>${escapeHtml(prompt)}</strong>
    </article>
    <article class="summary-card">
      <span>Max confidence</span>
      <strong>${formatNumber(analysis.max_confidence)}</strong>
    </article>
    <article class="summary-card">
      <span>Entity count</span>
      <strong>${analysis.entity_count}</strong>
    </article>
    <article class="summary-card">
      <span>Detected labels</span>
      <strong>${(analysis.detected_labels || []).join(", ") || "none"}</strong>
    </article>
  `;

  spansTarget.innerHTML = renderSpansMarkup(analysis.spans || []);
}

function renderFirewallSummary(firewall) {
  const target = document.getElementById("firewall-summary");
  if (!firewall) {
    target.innerHTML = `
      <article class="summary-card"><span>Firewall</span><strong>не запускался</strong></article>
      <article class="summary-card"><span>Причина</span><strong>нет поддержанного MCP tools/call</strong></article>
    `;
    return;
  }

  target.innerHTML = `
    <article class="summary-card">
      <span>Decision</span>
      <strong><span class="badge decision-${firewall.decision}">${firewall.decision}</span></strong>
    </article>
    <article class="summary-card">
      <span>Risk score</span>
      <strong>${formatNumber(firewall.risk_score)}</strong>
    </article>
    <article class="summary-card">
      <span>Decision source</span>
      <strong>${firewall.decision_source?.source || "n/a"}</strong>
    </article>
    <article class="summary-card">
      <span>Trigger</span>
      <strong>${firewall.decision_source?.detail || "n/a"}</strong>
    </article>
    <article class="summary-card full">
      <span>Rationale</span>
      <strong>${escapeHtml(firewall.rationale || "—")}</strong>
    </article>
  `;
}

function renderRuleMatches(matches) {
  const target = document.getElementById("rule-matches");
  if (!matches.length) {
    target.innerHTML = `<p class="empty-state">Явных rule-based срабатываний нет.</p>`;
    return;
  }
  target.innerHTML = matches
    .map(
      (match) => `
        <article class="list-item tone-${match.severity}">
          <div class="card-head">
            <strong>${match.name}</strong>
            <span class="badge decision-${match.severity === "block" ? "block" : "warn"}">${match.severity}</span>
          </div>
          <p>${escapeHtml(match.reason)}</p>
        </article>
      `
    )
    .join("");
}

function renderFirewallSpans(spans) {
  document.getElementById("firewall-spans").innerHTML = renderSpansMarkup(spans);
}

function renderSpansMarkup(spans) {
  if (!spans.length) {
    return `<p class="empty-state">Сущности не найдены.</p>`;
  }
  return spans
    .map(
      (span) => `
        <article class="span-chip tone-${span.label}">
          <div class="card-head">
            <strong>${span.label}</strong>
            <span>${formatNumber(span.score)}</span>
          </div>
          <p>${escapeHtml(span.text)}</p>
          <small>${formatSpanBounds(span)}</small>
        </article>
      `
    )
    .join("");
}

function formatSpanBounds(span) {
  if (Number.isInteger(span.start_char) && Number.isInteger(span.end_char)) {
    return `chars ${span.start_char}–${span.end_char}`;
  }
  return `tokens ${span.start_token}–${span.end_token}`;
}

function formatNumber(value, digits = 4) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(digits) : "0.0000";
}

function formatInterpretationStatus(value) {
  return {
    supported: "готов к разбору",
    incomplete: "недостаточно данных",
    unknown: "вне сценария",
    not_exported: "не экспортирован",
  }[value] || value || "unknown";
}

function shortenPath(value) {
  const text = String(value || "");
  if (text.length <= 42) return text;
  return `…${text.slice(-42)}`;
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

document.addEventListener("DOMContentLoaded", init);
