const state = {
  raw: null,
  currentCase: null,
};

const CATEGORY_META = {
  dotenv: {
    tone: "dotenv",
    strapline: "Файлы окружения",
    examples: [".env", ".env.local", ".env.production"],
    note: "Такие имена чаще всего ведут к файлам с секретами и конфигами среды.",
  },
  env_access_pattern: {
    tone: "env_access_pattern",
    strapline: "Доступ к переменным окружения",
    examples: ['process.env.OPENAI_API_KEY', 'os.environ["DB_PASSWORD"]', 'getenv("TOKEN")'],
    note: "Это кодовые паттерны чтения секретов из окружения, а не просто произвольный JavaScript или Python.",
  },
  private_url: {
    tone: "private_url",
    strapline: "Внутренние и чувствительные URL",
    examples: [
      "https://internal-api.company.local",
      "https://service.local?token=...",
      "http://169.254.169.254/latest/meta-data/",
    ],
    note: "Сюда относятся internal URL и ссылки с token, key, access_token или другими чувствительными параметрами.",
  },
  secret_name: {
    tone: "secret_name",
    strapline: "Имена секретов",
    examples: ["GITHUB_TOKEN", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY"],
    note: "Это именно имена переменных и секретов, а не их фактические значения.",
  },
  secret_value: {
    tone: "secret_value",
    strapline: "Значения токенов и ключей",
    examples: ["sk-proj-...", "ghp_xxxxx", "Bearer eyJ..."],
    note: "Модель должна отдельно ловить token-like строки, даже если название секрета не указано рядом.",
  },
  sensitive_path: {
    tone: "sensitive_path",
    strapline: "Чувствительные пути и конфиги",
    examples: ["/workspace/project/.env", "/var/run/secrets/kubernetes.io", "/Users/demo/.ssh/id_rsa"],
    note: "Это не любой path, а именно путь к секретам, ключам, .env и внутренним конфигам.",
  },
};

async function init() {
  const response = await fetch("data/demo.json");
  const data = await response.json();
  state.raw = data;

  renderHero(data);
  renderComparison(data.model_comparison || []);
  renderExamples(data.cases || []);
  renderFocus(data.policy || {});
  renderCategoryMap(data.categories || []);
  renderCategories(data.categories || []);

  const firstCase = pickFeaturedCase(data.cases || []);
  if (firstCase) {
    document.getElementById("prompt-input").value = firstCase.prompt;
    renderCase(markAsExported(firstCase));
  }

  document.getElementById("run-check").addEventListener("click", runLookup);
  document.getElementById("random-check").addEventListener("click", useRandomCase);
}

function runLookup() {
  const prompt = normalizeWhitespace(document.getElementById("prompt-input").value);
  const match = (state.raw?.cases || []).find((item) => item.normalized_prompt === prompt);

  if (match) {
    renderCase(markAsExported(match));
    return;
  }

  renderCase(synthesizeLivePreview(prompt));
}

function useRandomCase() {
  const cases = state.raw?.cases || [];
  if (!cases.length) return;
  const currentPrompt = normalizeWhitespace(document.getElementById("prompt-input").value);
  const pool = cases.filter((item) => item.normalized_prompt !== currentPrompt);
  const choice = (pool.length ? pool : cases)[Math.floor(Math.random() * (pool.length ? pool : cases).length)];
  if (!choice) return;
  document.getElementById("prompt-input").value = choice.prompt;
  renderCase(markAsExported(choice));
  document.getElementById("prompt-input").focus();
}

function markAsExported(item) {
  return {
    ...item,
    analysis_mode: "exported",
  };
}

function renderHero(data) {
  document.getElementById("active-model").textContent = formatCheckpointName(data.meta?.model_path || "unknown");
  document.getElementById("request-count").textContent = String(data.meta?.request_count || 0);
}

function renderComparison(rows) {
  const target = document.getElementById("comparison-grid");
  target.innerHTML = "";

  rows.forEach((row) => {
    const isActiveExport = Boolean(row.is_active_export);
    const card = document.createElement("article");
    card.className = `comparison-card${isActiveExport ? " is-primary" : ""}`;
    card.innerHTML = `
      <div class="card-head">
        <strong>${row.label}</strong>
        <span>${isActiveExport ? "active export" : `threshold ${formatNumber(row.threshold, 2)}`}</span>
      </div>
      <div class="metric-grid">
        <div><span>precision</span><strong>${formatNumber(row.precision)}</strong></div>
        <div><span>recall</span><strong>${formatNumber(row.recall)}</strong></div>
        <div><span>F1</span><strong>${formatNumber(row.f1)}</strong></div>
      </div>
      <div class="score-ribbon">
        <div class="score-line"><span>precision</span><div class="score-track"><div class="score-fill" style="width:${boundPercent(row.precision)}%;"></div></div></div>
        <div class="score-line"><span>recall</span><div class="score-track"><div class="score-fill" style="width:${boundPercent(row.recall)}%;"></div></div></div>
        <div class="score-line"><span>F1</span><div class="score-track"><div class="score-fill" style="width:${boundPercent(row.f1)}%;"></div></div></div>
      </div>
      <div class="confusion-strip">
        <span class="confusion-pill tp">TP <strong>${formatInteger(row.tp)}</strong></span>
        <span class="confusion-pill fp">FP <strong>${formatInteger(row.fp)}</strong></span>
        <span class="confusion-pill fn">FN <strong>${formatInteger(row.fn)}</strong></span>
      </div>
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
      renderCase(markAsExported(item));
    });
    target.appendChild(button);
  });
}

function renderFocus(policy) {
  const target = document.getElementById("focus-grid");
  if (!target) return;
  const cards = [
    {
      title: "Транспорты, которые реально участвуют в demo",
      tone: "neutral",
      items: policy.allowed_transports || [],
    },
    {
      title: "Safe file roots",
      tone: "safe",
      items: policy.safe_file_roots || [],
    },
    {
      title: "Blocked hosts",
      tone: "block",
      items: policy.blocked_hosts || [],
    },
    {
      title: "Blocked paths",
      tone: "block",
      items: policy.blocked_paths || [],
    },
    {
      title: "Чувствительные keyword-сигналы",
      tone: "warn",
      items: policy.sensitive_keywords || [],
    },
    {
      title: "Пороги эскалации",
      tone: "warn",
      items: [`warn: ${policy.warn_risk_threshold}`, `block: ${policy.block_risk_threshold}`],
    },
  ];

  target.innerHTML = cards
    .map(
      (card) => `
        <article class="focus-card tone-${card.tone}">
          <strong>${card.title}</strong>
          <div class="focus-list">
            ${card.items.map((item) => `<span class="focus-chip">${escapeHtml(item)}</span>`).join("")}
          </div>
        </article>
      `
    )
    .join("");
}

function renderCategories(categories) {
  const target = document.getElementById("categories-grid");
  target.innerHTML = categories
    .map((item) => {
      const meta = CATEGORY_META[item.name] || {};
      return `
        <article class="category-card tone-${meta.tone || item.name}">
          <div class="category-topline">
            <strong>${item.name}</strong>
            <span class="category-badge">${escapeHtml(meta.strapline || "Suspicious span")}</span>
          </div>
          <p>${item.description}</p>
          ${
            meta.examples?.length
              ? `<div class="category-examples">
                  ${meta.examples.map((example) => `<code>${escapeHtml(example)}</code>`).join("")}
                </div>`
              : ""
          }
          ${meta.note ? `<small class="category-note">${escapeHtml(meta.note)}</small>` : ""}
        </article>
      `;
    })
    .join("");
}

function renderCategoryMap(categories) {
  const target = document.getElementById("category-map");
  if (!target) return;
  target.innerHTML = `
    <div class="category-map-core">
      <span class="category-map-label">GLiNER + LoRA</span>
      <strong>suspicious MCP spans</strong>
      <p>6 доменных категорий для prompt-level и full-context анализа.</p>
    </div>
    <div class="category-map-ring">
      ${categories
        .map((item) => {
          const meta = CATEGORY_META[item.name] || {};
          return `
            <article class="category-map-node tone-${meta.tone || item.name}">
              <strong>${item.name}</strong>
              <span>${escapeHtml(meta.strapline || "Suspicious span")}</span>
            </article>
          `;
        })
        .join("")}
    </div>
  `;
}

function renderCase(item) {
  state.currentCase = item;

  const interpretation = item.interpretation || {};
  const firewall = item.firewall || null;

  document.getElementById("interpretation-status").textContent = formatInterpretationStatus(interpretation.status);
  document.getElementById("interpretation-json").textContent = JSON.stringify(interpretation, null, 2);
  document.getElementById("mcp-request-json").textContent = item.mcp_request ? JSON.stringify(item.mcp_request, null, 2) : "null";

  renderQuickOutcome(item);
  renderCasePipeline(item);
  renderPromptSummary(item, item.prompt_analysis, item.prompt, item.mcp_request, firewall);
  renderFirewallSummary(firewall);
  renderRuleMatches(firewall?.rule_matches || []);
  renderFirewallSpans(firewall?.privacy_assessment?.spans || []);
}

function renderQuickOutcome(item) {
  const target = document.getElementById("quick-outcome");
  const interpretation = item.interpretation || {};
  const firewall = item.firewall || null;
  const modeLabel = item.analysis_mode === "live_preview" ? "локальный preview" : "экспортированный кейс";

  if (!firewall) {
    target.innerHTML = `
      <article class="summary-card">
        <span>Статус</span>
        <strong>${escapeHtml(formatInterpretationStatus(interpretation.status))}</strong>
      </article>
      <article class="summary-card">
        <span>Что распознано</span>
        <strong>${escapeHtml(interpretation.intent || "unknown")}</strong>
      </article>
      <article class="summary-card full">
        <span>Что нужно дальше</span>
        <strong>${escapeHtml(interpretation.message || "Уточни запрос, чтобы можно было построить MCP tools/call.")}</strong>
      </article>
      <article class="summary-card full">
        <span>Источник</span>
        <strong>${modeLabel}</strong>
      </article>
    `;
    return;
  }

  target.innerHTML = `
    <article class="summary-card">
      <span>Итоговое решение</span>
      <strong><span class="badge decision-${firewall.decision}">${firewall.decision}</span></strong>
    </article>
    <article class="summary-card">
      <span>MCP tool</span>
      <strong>${escapeHtml(interpretation.tool_name || "n/a")}</strong>
    </article>
    <article class="summary-card">
      <span>Risk score</span>
      <strong>${formatNumber(firewall.risk_score)}</strong>
    </article>
    <article class="summary-card">
      <span>Что определило итог</span>
      <strong>${escapeHtml(firewall.decision_source?.detail || firewall.decision_source?.source || "n/a")}</strong>
    </article>
    <article class="summary-card full">
      <span>Краткое объяснение</span>
      <strong>${escapeHtml(firewall.rationale || "—")}</strong>
    </article>
    <article class="summary-card full">
      <span>Источник</span>
      <strong>${modeLabel}</strong>
    </article>
  `;
}

function renderPromptSummary(item, analysis, prompt, mcpRequest, firewall) {
  const summary = document.getElementById("prompt-summary");
  const spansTarget = document.getElementById("prompt-spans");
  const promptHighlight = document.getElementById("prompt-highlight");
  const requestHighlight = document.getElementById("request-highlight");

  if (!analysis) {
    summary.innerHTML = `
      <article class="summary-card"><span>Prompt</span><strong>${escapeHtml(prompt || "—")}</strong></article>
      <article class="summary-card"><span>Span count</span><strong>0</strong></article>
      <article class="summary-card"><span>Статус</span><strong>${escapeHtml(item?.interpretation?.message || "анализ не собран")}</strong></article>
    `;
    promptHighlight.innerHTML = `<p class="empty-state">Нет текста для анализа.</p>`;
    requestHighlight.innerHTML = `<p class="empty-state">Нет сформированного MCP-вызова для подсветки.</p>`;
    spansTarget.innerHTML = `<p class="empty-state">${escapeHtml(item?.interpretation?.message || "Сущности не найдены.")}</p>`;
    return;
  }

  const modeLabel = item.analysis_mode === "live_preview" ? "локальный preview" : "exported LoRA run";
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
    <article class="summary-card full">
      <span>Источник анализа</span>
      <strong>${modeLabel}</strong>
    </article>
  `;

  const requestText = mcpRequest ? JSON.stringify(mcpRequest, null, 2) : "";
  promptHighlight.innerHTML = renderHighlightMarkup(prompt, analysis.spans || [], buildRuleFragments(prompt, mcpRequest, firewall, "prompt"));
  requestHighlight.innerHTML = requestText
    ? renderHighlightMarkup(requestText, filterRequestHighlightSpans(firewall?.privacy_assessment?.spans || []), buildRuleFragments(requestText, mcpRequest, firewall, "request"))
    : `<p class="empty-state">Нет сформированного MCP-вызова для подсветки.</p>`;

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

function renderCasePipeline(item) {
  const target = document.getElementById("case-pipeline");
  if (!target) return;
  const promptAnalysis = item.prompt_analysis || {};
  const interpretation = item.interpretation || {};
  const firewall = item.firewall || {};
  const labels = (promptAnalysis.detected_labels || []).join(", ") || "none";
  const spanCount = promptAnalysis.entity_count || 0;
  const modeLabel = item.analysis_mode === "live_preview" ? "local preview" : "export";

  target.innerHTML = `
    <article class="pipeline-step">
      <span class="pipeline-index">01</span>
      <strong>Prompt</strong>
      <p>${escapeHtml(item.prompt || "—")}</p>
    </article>
    <article class="pipeline-step tone-${(promptAnalysis.detected_labels || [])[0] || "neutral"}">
      <span class="pipeline-index">02</span>
      <strong>Span review</strong>
      <p>${spanCount} span-ов; labels: ${escapeHtml(labels)}</p>
    </article>
    <article class="pipeline-step">
      <span class="pipeline-index">03</span>
      <strong>MCP tools/call</strong>
      <p>${escapeHtml(interpretation.tool_name || "n/a")} · ${modeLabel}</p>
    </article>
    <article class="pipeline-step tone-${firewall.decision || "warn"}">
      <span class="pipeline-index">04</span>
      <strong>Firewall outcome</strong>
      <p>${escapeHtml(firewall.decision || "n/a")} · ${escapeHtml(firewall.decision_source?.source || "n/a")}</p>
    </article>
  `;
}

function pickFeaturedCase(cases) {
  return cases.find((item) => item.firewall?.decision === "block")
    || cases.find((item) => item.firewall?.decision === "warn")
    || cases[0]
    || null;
}

function synthesizeLivePreview(prompt) {
  const normalizedPrompt = normalizeWhitespace(prompt);
  const policy = state.raw?.policy || {};
  const interpretation = interpretPrompt(normalizedPrompt, policy);
  const promptAnalysis = analyzeSuspiciousSpans(normalizedPrompt);
  const mcpRequest = interpretation.status === "supported"
    ? buildMcpRequestFromInterpretation(interpretation)
    : null;
  const firewall = interpretation.status === "supported"
    ? evaluateFirewallPreview(normalizedPrompt, interpretation, promptAnalysis, policy)
    : null;

  return {
    id: `live-preview-${Date.now()}`,
    title: "Локальный preview",
    prompt: normalizedPrompt,
    normalized_prompt: normalizedPrompt,
    notes: "Живой browser-side preview для нового текста.",
    analysis_mode: "live_preview",
    prompt_analysis: promptAnalysis,
    interpretation,
    mcp_request: mcpRequest,
    firewall,
  };
}

function analyzeSuspiciousSpans(text) {
  const source = String(text || "");
  if (!source) {
    return {
      context_text: source,
      max_confidence: 0,
      detected_labels: [],
      entity_count: 0,
      sensitive_entity_count: 0,
      spans: [],
    };
  }

  const spans = [];
  const addSpan = (label, rawText, start, end, score) => {
    if (!rawText || start < 0 || end <= start) return;
    spans.push({
      label,
      text: rawText,
      score,
      start_char: start,
      end_char: end,
    });
  };

  collectRegexSpans(source, /(^|[\s"'`(])(\.env(?:\.[A-Za-z0-9_-]+)?|[A-Za-z0-9_-]+\.env)(?=$|[\s"'`),.;:])/g, "dotenv", 0.83, 2, addSpan);
  collectRegexSpans(source, /\b(?:process\.env(?:\.[A-Z0-9_]+|\[['"][A-Z0-9_]+['"]\])|os\.environ\[['"][A-Z0-9_]+['"]\]|getenv\(['"][A-Z0-9_]+['"]\))\b/g, "env_access_pattern", 0.91, 0, addSpan);
  collectPrivateUrlSpans(source, addSpan);
  collectRegexSpans(source, /\b(?:[A-Z][A-Z0-9_]{2,})\b/g, "secret_name", 0.86, 0, addSpan, (value) => /(TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL|DATABASE_URL|OPENAI|GITHUB|AWS|PRIVATE_KEY|ACCESS_KEY)/.test(value));
  collectRegexSpans(source, /\b(?:Bearer\s+[A-Za-z0-9._-]{10,}|ghp_[A-Za-z0-9]{10,}|sk(?:-proj)?-[A-Za-z0-9_-]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g, "secret_value", 0.94, 0, addSpan);
  collectSensitivePathSpans(source, addSpan);

  const deduped = collapseOverlappingSpans(spans);
  const labels = [...new Set(deduped.map((span) => span.label))];
  const maxConfidence = deduped.reduce((max, span) => Math.max(max, Number(span.score) || 0), 0);

  return {
    context_text: source,
    max_confidence: maxConfidence,
    detected_labels: labels,
    entity_count: deduped.length,
    sensitive_entity_count: deduped.length,
    spans: deduped,
  };
}

function collectRegexSpans(text, regex, label, score, captureGroup, addSpan, predicate = null) {
  const matches = text.matchAll(regex);
  for (const match of matches) {
    const value = captureGroup > 0 ? match[captureGroup] : match[0];
    if (!value) continue;
    if (predicate && !predicate(value)) continue;
    const fullMatch = match[0];
    const offset = captureGroup > 0 ? fullMatch.indexOf(value) : 0;
    const start = match.index + offset;
    addSpan(label, value, start, start + value.length, score);
  }
}

function collectPrivateUrlSpans(text, addSpan) {
  for (const match of text.matchAll(/\bhttps?:\/\/[^\s"'<>]+/g)) {
    const url = match[0];
    const host = extractHost(url);
    const lower = url.toLowerCase();
    const isSensitive = isPrivateHost(host)
      || /\.(local|internal)\b/.test(host)
      || /(?:token|access_token|api[_-]?key|key|secret)=/.test(lower);
    if (!isSensitive) continue;
    addSpan("private_url", url, match.index, match.index + url.length, host === "169.254.169.254" ? 0.98 : 0.9);
  }
}

function collectSensitivePathSpans(text, addSpan) {
  const patterns = [
    /\/(?:[\w.-]+\/)*(?:\.env(?:\.[\w-]+)?|id_rsa|authorized_keys|known_hosts)\b/g,
    /\/(?:[\w.-]+\/)*(?:prod-secrets\.ya?ml|secrets?(?:\/[\w./-]+)*)\b/g,
    /\/var\/run\/secrets(?:\/[\w./-]+)?\b/g,
    /\/proc\/self\/environ\b/g,
    /\/etc\/passwd\b/g,
    /\/(?:Users|home)\/[\w.-]+\/\.ssh(?:\/[\w.-]+)?\b/g,
  ];

  patterns.forEach((regex) => {
    for (const match of text.matchAll(regex)) {
      const value = match[0];
      addSpan("sensitive_path", value, match.index, match.index + value.length, 0.92);
    }
  });
}

function collapseOverlappingSpans(spans) {
  const priority = {
    secret_value: 6,
    secret_name: 5,
    env_access_pattern: 4,
    sensitive_path: 3,
    private_url: 2,
    dotenv: 1,
  };

  const sorted = [...spans].sort((left, right) => {
    if (left.start_char !== right.start_char) return left.start_char - right.start_char;
    if ((priority[right.label] || 0) !== (priority[left.label] || 0)) return (priority[right.label] || 0) - (priority[left.label] || 0);
    if ((right.end_char - right.start_char) !== (left.end_char - left.start_char)) return (right.end_char - right.start_char) - (left.end_char - left.start_char);
    return (Number(right.score) || 0) - (Number(left.score) || 0);
  });

  const accepted = [];
  sorted.forEach((candidate) => {
    const overlaps = accepted.some((item) => candidate.start_char < item.end_char && candidate.end_char > item.start_char);
    if (!overlaps) accepted.push(candidate);
  });

  return accepted.sort((left, right) => left.start_char - right.start_char);
}

function buildMcpRequestFromInterpretation(interpretation) {
  return {
    jsonrpc: "2.0",
    id: "gliner-lora-live-preview",
    method: "tools/call",
    params: {
      name: interpretation.tool_name,
      arguments: interpretation.arguments,
    },
  };
}

function evaluateFirewallPreview(prompt, interpretation, promptAnalysis, policy) {
  const contextText = buildContextText(interpretation);
  const contextAnalysis = analyzeSuspiciousSpans(contextText);
  const ruleMatches = evaluatePreviewRules(interpretation, policy, promptAnalysis, contextAnalysis);
  const riskScore = scorePreviewRisk(prompt, interpretation, promptAnalysis, contextAnalysis, ruleMatches, policy);
  const decision = derivePreviewDecision(riskScore, ruleMatches, policy);
  const decisionSource = determinePreviewDecisionSource(riskScore, ruleMatches, policy);

  return {
    risk_score: riskScore,
    decision,
    rationale: buildPreviewRationale(decision, ruleMatches, riskScore, promptAnalysis, contextAnalysis, policy),
    features: {
      transport_type: "stdio",
      jsonrpc_method: "tools/call",
      tool_name: interpretation.tool_name,
      arg_count: Object.keys(interpretation.arguments || {}).length,
      payload_size: JSON.stringify(interpretation.arguments || {}).length + prompt.length,
      response_size: 0,
      response_time_ms: 0,
      is_error: false,
      tools_called_last_session: 0,
      failed_calls_last_session: 0,
      sensitive_path_flag: hasLabel(promptAnalysis, "sensitive_path") || hasLabel(promptAnalysis, "dotenv"),
      external_url_flag: interpretation.tool_name === "web.fetch",
      private_ip_flag: hasBlockedHost(interpretation.arguments?.url || "", policy),
      sensitive_keyword_flag: hasSensitiveKeywordsText(prompt, policy),
      dangerous_command_flag: false,
      excessive_scope_flag: /\b(all|все|recursive|entire|полностью)\b/i.test(prompt),
      inline_secret_flag: hasLabel(promptAnalysis, "secret_value"),
      exfiltration_flag: interpretation.tool_name === "web.fetch" && (hasLabel(promptAnalysis, "secret_value") || hasLabel(promptAnalysis, "secret_name")),
      repeated_tool_flag: false,
      full_context_sensitive_flag: contextAnalysis.entity_count > 0,
      full_context_high_risk_flag: riskScore >= Number(policy.block_risk_threshold || 0.75),
      full_context_entity_count: contextAnalysis.entity_count,
      full_context_sensitive_entity_count: contextAnalysis.sensitive_entity_count,
      full_context_max_confidence: contextAnalysis.max_confidence,
    },
    rule_matches: ruleMatches,
    decision_source: decisionSource,
    privacy_assessment: contextAnalysis,
  };
}

function buildContextText(interpretation) {
  const args = interpretation.arguments || {};
  const parts = [
    "client_id = agent-1",
    `server_id = ${interpretation.server_id || "unknown-server"}`,
    "transport = stdio",
    "method = tools/call",
    `tool_name = ${interpretation.tool_name || "unknown-tool"}`,
  ];

  Object.entries(args).forEach(([key, value]) => {
    parts.push(`${key} = ${String(value)}`);
  });

  return parts.join(" ");
}

function evaluatePreviewRules(interpretation, policy, promptAnalysis, contextAnalysis) {
  const matches = [];
  const path = String(interpretation.arguments?.path || "");
  const query = String(interpretation.arguments?.query || "");
  const url = String(interpretation.arguments?.url || "");

  if (path && (policy.blocked_paths || []).some((blocked) => path.includes(blocked))) {
    matches.push({ name: "sensitive_path_access", severity: "block", reason: `Обнаружен чувствительный путь: ${path}.` });
  }

  if (path.startsWith("/private") && interpretation.tool_name === "filesystem.read_file") {
    matches.push({ name: "private_backend_path_access", severity: "block", reason: "Попытка доступа к приватному backend-path через MCP." });
  }

  if (path && interpretation.tool_name === "filesystem.read_file" && !(policy.safe_file_roots || []).some((root) => path.startsWith(root))) {
    matches.push({ name: "path_outside_safe_roots", severity: "warn", reason: "Операция чтения направлена на путь вне safe roots." });
  }

  if (url) {
    const host = extractHost(url);
    if (host && ((policy.blocked_hosts || []).includes(host) || isPrivateHost(host) || /\.(local|internal)\b/.test(host))) {
      matches.push({ name: "private_address_access", severity: "block", reason: `Обнаружено обращение к приватному или служебному хосту: ${host}.` });
    }

    if (/(?:token|access_token|api[_-]?key|key|secret)=/i.test(url)) {
      matches.push({ name: "credential_in_url", severity: "warn", reason: "В URL присутствует чувствительный параметр доступа." });
    }
  }

  if (interpretation.tool_name === "filesystem.search" && (hasLabel(promptAnalysis, "secret_name") || hasLabel(promptAnalysis, "secret_value") || hasLabel(promptAnalysis, "dotenv") || hasLabel(promptAnalysis, "env_access_pattern"))) {
    matches.push({ name: "secret_search_request", severity: "warn", reason: `Поисковый запрос ориентирован на секреты или env-паттерны: ${query || "suspicious query"}.` });
  }

  if (!matches.some((match) => match.severity === "block") && contextAnalysis.entity_count > 0) {
    matches.push({ name: "full_context_sensitive_request", severity: "warn", reason: `Full-context слой отметил чувствительные span-ы: ${(contextAnalysis.detected_labels || []).join(", ")}.` });
  }

  return deduplicateMatches(matches);
}

function scorePreviewRisk(prompt, interpretation, promptAnalysis, contextAnalysis, ruleMatches, policy) {
  let score = 0.05;
  if (hasLabel(promptAnalysis, "sensitive_path")) score += 0.45;
  if (hasLabel(promptAnalysis, "dotenv")) score += 0.18;
  if (hasLabel(promptAnalysis, "env_access_pattern")) score += 0.22;
  if (hasLabel(promptAnalysis, "private_url")) score += 0.35;
  if (hasLabel(promptAnalysis, "secret_name")) score += 0.18;
  if (hasLabel(promptAnalysis, "secret_value")) score += 0.28;
  if ((promptAnalysis.detected_labels || []).length >= 2) score += 0.08;
  if (/\b(all|все|recursive|entire|полностью)\b/i.test(prompt)) score += 0.08;
  if (interpretation.tool_name === "web.fetch" && (hasLabel(promptAnalysis, "private_url") || hasLabel(promptAnalysis, "secret_value"))) score += 0.12;
  if (ruleMatches.some((match) => match.severity === "block")) score = Math.max(score, Number(policy.block_risk_threshold || 0.75) + 0.1);
  if (!ruleMatches.some((match) => match.severity === "block") && ruleMatches.some((match) => match.severity === "warn")) score = Math.max(score, Number(policy.warn_risk_threshold || 0.4) + 0.02);
  if (contextAnalysis.max_confidence >= 0.9) score += 0.05;
  return Math.min(score, 0.99);
}

function derivePreviewDecision(riskScore, ruleMatches, policy) {
  if (ruleMatches.some((match) => match.severity === "block")) return "block";
  if (riskScore >= Number(policy.block_risk_threshold || 0.75)) return "block";
  if (ruleMatches.some((match) => match.severity === "warn") || riskScore >= Number(policy.warn_risk_threshold || 0.4)) return "warn";
  return "allow";
}

function determinePreviewDecisionSource(riskScore, ruleMatches, policy) {
  const blockMatch = ruleMatches.find((match) => match.severity === "block");
  if (blockMatch) {
    return {
      source: "rule-based",
      detail: blockMatch.name,
    };
  }

  const warnMatch = ruleMatches.find((match) => match.severity === "warn");
  if (riskScore >= Number(policy.block_risk_threshold || 0.75)) {
    return {
      source: "ml-preview",
      detail: "risk score above block threshold",
    };
  }

  if (warnMatch) {
    return {
      source: "rule-based",
      detail: warnMatch.name,
    };
  }

  if (riskScore >= Number(policy.warn_risk_threshold || 0.4)) {
    return {
      source: "ml-preview",
      detail: "risk score above warn threshold",
    };
  }

  return {
    source: "safe-preview",
    detail: "no escalation triggered",
  };
}

function buildPreviewRationale(decision, ruleMatches, riskScore, promptAnalysis, contextAnalysis, policy) {
  const blockReasons = ruleMatches.filter((match) => match.severity === "block").map((match) => match.reason);
  if (blockReasons.length) return blockReasons.join("; ");

  const warnReasons = ruleMatches.filter((match) => match.severity === "warn").map((match) => match.reason);
  if (warnReasons.length) return warnReasons.join("; ");

  if (decision === "block" && riskScore >= Number(policy.block_risk_threshold || 0.75)) {
    return `Локальный preview поднял риск до ${formatNumber(riskScore)} за счёт span-комбинации: ${(promptAnalysis.detected_labels || []).join(", ") || "none"}.`;
  }

  if (decision === "warn") {
    return `Запрос выглядит подозрительно: prompt-level labels = ${(promptAnalysis.detected_labels || []).join(", ") || "none"}, full-context labels = ${(contextAnalysis.detected_labels || []).join(", ") || "none"}.`;
  }

  return "Явных чувствительных span-ов и блокирующих policy-сигналов не найдено.";
}

function buildRuleFragments(text, mcpRequest, firewall, mode) {
  const fragments = new Set();
  const sourceText = String(text || "");
  const args = mcpRequest?.params?.arguments || {};

  Object.values(args)
    .filter((value) => typeof value === "string")
    .forEach((value) => {
      if (value && sourceText.includes(value)) {
        fragments.add(value);
      }
    });

  (firewall?.rule_matches || []).forEach((match) => {
    const lowerReason = String(match.reason || "").toLowerCase();
    if (lowerReason.includes("path") || lowerReason.includes("файл")) {
      Object.values(args)
        .filter((value) => typeof value === "string" && value.includes("/"))
        .forEach((value) => {
          if (sourceText.includes(value)) fragments.add(value);
        });
    }

    if (lowerReason.includes("host") || lowerReason.includes("address") || lowerReason.includes("url")) {
      Object.values(args)
        .filter((value) => typeof value === "string" && /https?:\/\/|localhost|169\.254|127\.0\.0\.1|internal/i.test(value))
        .forEach((value) => {
          if (sourceText.includes(value)) fragments.add(value);
        });
    }

    if (lowerReason.includes("secret") || lowerReason.includes("token") || lowerReason.includes("keyword") || lowerReason.includes("env")) {
      Object.values(args)
        .filter((value) => typeof value === "string")
        .forEach((value) => {
          for (const chunk of value.split(/[\s,?&=]+/)) {
            if (chunk.length >= 4 && sourceText.includes(chunk) && /(token|secret|password|key|env|ghp_|sk-|bearer)/i.test(chunk)) {
              fragments.add(chunk);
            }
          }
        });
    }
  });

  if (mode === "prompt" && !fragments.size && (firewall?.rule_matches || []).length) {
    Object.values(args)
      .filter((value) => typeof value === "string" && sourceText.includes(value))
      .forEach((value) => fragments.add(value));
  }

  return [...fragments];
}

function filterRequestHighlightSpans(spans) {
  return (spans || []).filter((span) => {
    const text = String(span.text || "");
    return /\/|https?:\/\/|token|secret|password|key|env|ghp_|sk-|bearer|internal|localhost|169\.254|127\.0\.0\.1/i.test(text);
  });
}

function renderHighlightMarkup(text, spans, extraFragments = []) {
  if (!text) {
    return `<p class="empty-state">Нет текста для подсветки.</p>`;
  }

  let markup = null;
  const charSpans = (spans || []).filter((span) => Number.isInteger(span.start_char) && Number.isInteger(span.end_char));

  if (charSpans.length) {
    markup = renderMarkupFromCharSpans(text, charSpans);
  } else {
    const fragments = [
      ...(spans || []).map((span) => span.text).filter(Boolean),
      ...extraFragments,
    ];
    markup = renderMarkupFromFragments(text, fragments);
  }

  return markup || `<p class="empty-state">Для этого кейса явная инлайн-подсветка не выделилась.</p>`;
}

function renderMarkupFromCharSpans(text, spans) {
  const safeSpans = [...spans]
    .filter((span) => span.end_char > span.start_char)
    .sort((left, right) => left.start_char - right.start_char);

  if (!safeSpans.length) return "";

  let cursor = 0;
  let html = "";

  safeSpans.forEach((span) => {
    html += escapeHtml(text.slice(cursor, span.start_char));
    html += `<mark class="text-mark tone-${span.label}">${escapeHtml(text.slice(span.start_char, span.end_char))}</mark>`;
    cursor = span.end_char;
  });

  html += escapeHtml(text.slice(cursor));
  return `<pre class="highlight-code">${html}</pre>`;
}

function renderMarkupFromFragments(text, fragments) {
  const unique = [...new Set((fragments || []).map((item) => String(item || "").trim()).filter(Boolean))]
    .sort((left, right) => right.length - left.length);

  if (!unique.length) return "";

  let workingText = String(text);
  const replacements = [];

  unique.forEach((fragment, index) => {
    const escaped = fragment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(escaped, "g");
    if (!regex.test(workingText)) return;
    const placeholder = `__HIGHLIGHT_${index}__`;
    workingText = workingText.replace(regex, placeholder);
    replacements.push({
      placeholder,
      markup: `<mark class="text-mark tone-highlight">${escapeHtml(fragment)}</mark>`,
    });
  });

  if (!replacements.length) return "";

  let html = escapeHtml(workingText);
  replacements.forEach(({ placeholder, markup }) => {
    html = html.replaceAll(placeholder, markup);
  });

  return `<pre class="highlight-code">${html}</pre>`;
}

function interpretPrompt(prompt, policy) {
  const normalizedPrompt = normalizeWhitespace(prompt);
  const lower = normalizedPrompt.toLowerCase();
  const path = extractPath(normalizedPrompt);
  const url = extractUrl(normalizedPrompt);
  const envStyleQuery = hasEnvPatternSearchIntent(normalizedPrompt);

  if (!normalizedPrompt) {
    return {
      status: "unknown",
      intent: "unknown",
      confidence: 0,
      message: "Пустой запрос не может быть интерпретирован как MCP-сценарий.",
    };
  }

  if (envStyleQuery) {
    return {
      status: "supported",
      intent: "search",
      confidence: 0.91,
      tool_name: "filesystem.search",
      server_id: policy.tool_server_map?.["filesystem.search"] || "filesystem-server",
      arguments: {
        path: path || "/workspace/project",
        query: envStyleQuery,
      },
      message: "Запрос интерпретирован как поиск env-паттернов и секретов по репозиторию.",
    };
  }

  if (hasFetchIntent(lower) || url) {
    if (!url) {
      return {
        status: "incomplete",
        intent: "web_fetch",
        confidence: 0.52,
        missing: ["url"],
        message: "Распознан web-сценарий, но в запросе не указан конкретный URL.",
      };
    }

    return {
      status: "supported",
      intent: "web_fetch",
      confidence: 0.95,
      tool_name: "web.fetch",
      server_id: policy.tool_server_map?.["web.fetch"] || "http-server",
      arguments: { url },
      message: "Запрос интерпретирован как web-fetch вызов.",
    };
  }

  if (hasReadIntent(lower, path)) {
    if (!path) {
      return {
        status: "incomplete",
        intent: "read_file",
        confidence: 0.74,
        missing: ["path"],
        message: "Распознан сценарий чтения файла, но не указан конкретный путь.",
      };
    }

    return {
      status: "supported",
      intent: "read_file",
      confidence: 0.92,
      tool_name: "filesystem.read_file",
      server_id: policy.tool_server_map?.["filesystem.read_file"] || "filesystem-server",
      arguments: { path },
      message: "Запрос интерпретирован как чтение файла через filesystem.read_file.",
    };
  }

  if (hasSearchIntent(lower)) {
    const query = cleanupSearchQuery(normalizedPrompt);
    if (!query || query.length < 3) {
      return {
        status: "incomplete",
        intent: "search",
        confidence: 0.61,
        missing: ["query"],
        message: "Распознан поисковый сценарий, но запрос недостаточно конкретен для построения search-вызова.",
      };
    }

    return {
      status: "supported",
      intent: "search",
      confidence: 0.83,
      tool_name: "filesystem.search",
      server_id: policy.tool_server_map?.["filesystem.search"] || "filesystem-server",
      arguments: {
        path: path || "/workspace/project",
        query,
      },
      message: "Запрос интерпретирован как поиск по файловому дереву.",
    };
  }

  return {
    status: "unknown",
    intent: "unknown",
    confidence: 0.18,
    message: "Запрос вне поддерживаемых демо-сценариев. Preview понимает чтение файла, web-fetch и поиск.",
  };
}

function hasReadIntent(lower, path) {
  if (/\b(read|cat|open file|show file)\b/i.test(lower)) return true;
  if (/(прочитай|прочти|открой файл|покажи файл|выведи файл|содержимое файла)/i.test(lower)) return true;
  if (path && /(файл|file|read|прочитай|прочти|открой|покажи)/i.test(lower)) return true;
  return false;
}

function hasFetchIntent(lower) {
  return /(fetch|http|url|сайт|страниц|страницу|перейди|скачай|запроси|web[- ]?запрос|открой\s+(?!файл))/i.test(lower);
}

function hasSearchIntent(lower) {
  return /(найди|ищи|поиск|search|find|grep|поищи|проверь.*(секрет|token|password|key|env))/i.test(lower);
}

function hasEnvPatternSearchIntent(text) {
  const source = String(text || "");
  const lower = source.toLowerCase();
  const hasSearchVerb = /(где используется|где встречается|найди|ищи|поиск|search|find|grep|проверь)/i.test(lower);
  const envPatternSource = String.raw`(?:process\.env(?:\.[A-Z0-9_]+|\[['"][A-Z0-9_]+['"]\])|os\.environ\[['"][A-Z0-9_]+['"]\]|getenv\(['"][A-Z0-9_]+['"]\)|\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL|DATABASE_URL|OPENAI|GITHUB|AWS)[A-Z0-9_]*\b)`;
  const envPatternCheck = new RegExp(envPatternSource);
  const envPatternGlobal = new RegExp(envPatternSource, "g");

  if (!hasSearchVerb || !envPatternCheck.test(source)) {
    return "";
  }

  const matches = [...source.matchAll(envPatternGlobal)].map((match) => match[0]);
  return matches.join(" ");
}

function extractUrl(text) {
  return (String(text || "").match(/\bhttps?:\/\/[^\s"'<>]+/i) || [])[0] || "";
}

function extractPath(text) {
  const direct = (String(text || "").match(/(?:\/[\w./-]+|\.\.?\/[\w./-]+|[\w.-]+\.(?:env|json|ya?ml|md|txt|ini|toml))/) || [])[0] || "";
  return normalizePathCandidate(direct);
}

function cleanupSearchQuery(prompt) {
  return normalizeWhitespace(
    String(prompt || "")
      .replace(/^(найди|ищи|поиск|search|find|grep|поищи|проверь)/i, "")
      .replace(/\b(в репозитории|в проекте|по проекту|во всех файлах)\b/gi, "")
  );
}

function normalizeWhitespace(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function normalizePathCandidate(candidate) {
  if (!candidate) return "";

  let path = String(candidate).trim().replace(/^["']|["']$/g, "").replace(/[),.;:]+$/g, "");
  if (!path || /^https?:\/\//i.test(path)) return "";

  if (path.startsWith("/")) return path;
  if (path.startsWith("./")) path = path.slice(2);
  if (path.startsWith("../")) path = path.replace(/^(\.\.\/)+/, "");
  if (!path) return "";

  return `/workspace/project/${path}`;
}

function hasLabel(analysis, label) {
  return (analysis?.detected_labels || []).includes(label);
}

function hasSensitiveKeywordsText(text, policy) {
  const lower = String(text || "").toLowerCase();
  return (policy.sensitive_keywords || []).some((keyword) => lower.includes(String(keyword).toLowerCase()));
}

function hasBlockedHost(url, policy) {
  const host = extractHost(url);
  return Boolean(host) && (((policy.blocked_hosts || []).includes(host)) || isPrivateHost(host));
}

function extractHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isPrivateHost(host) {
  return (
    host === "localhost"
    || host === "127.0.0.1"
    || host === "169.254.169.254"
    || host === "0.0.0.0"
    || host === "::1"
    || host.startsWith("10.")
    || host.startsWith("192.168.")
    || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)
  );
}

function deduplicateMatches(matches) {
  const seen = new Set();
  return matches.filter((match) => {
    if (seen.has(match.name)) return false;
    seen.add(match.name);
    return true;
  });
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

function formatInteger(value) {
  const number = Number(value);
  return Number.isFinite(number) ? String(Math.round(number)) : "—";
}

function formatInterpretationStatus(value) {
  return {
    supported: "готов к разбору",
    incomplete: "недостаточно данных",
    unknown: "вне сценария",
  }[value] || value || "unknown";
}

function shortenPath(value) {
  const text = String(value || "");
  if (text.length <= 42) return text;
  return `…${text.slice(-42)}`;
}

function formatCheckpointName(value) {
  const text = String(value || "");
  if (!text) return "unknown";
  const parts = text.split("/").filter(Boolean);
  const tail = parts.slice(-2);
  if (tail.length === 2) {
    return `${tail[0]} / ${tail[1]}`;
  }
  return shortenPath(text);
}

function boundPercent(value) {
  return Math.max(0, Math.min(100, Number(value) * 100));
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

document.addEventListener("DOMContentLoaded", init);
