const state = {
  raw: null,
  demoSession: createDemoSession(),
};

function createDemoSession() {
  return {
    sessionId: "demo-session",
    totalCalls: 0,
    failedCalls: 0,
    lastToolName: "",
    sensitiveHits: 0,
  };
}

async function init() {
  const response = await fetch("data/dashboard.json");
  const data = await response.json();
  state.raw = data;

  renderHero(data);
  renderExamples(data.demo || {});
  populateSelect("demo-transport", data.demo?.policy?.allowed_transports || []);

  const featuredPrompt = pickFeaturedPrompt(data.demo?.sample_prompts || []);
  if (featuredPrompt) {
    document.getElementById("demo-prompt").value = featuredPrompt;
  }

  document.getElementById("demo-run").addEventListener("click", runDemo);
  document.getElementById("demo-random").addEventListener("click", () => {
    const randomPrompt = pickRandomPrompt(data.demo?.sample_prompts || [], document.getElementById("demo-prompt").value);
    if (randomPrompt) {
      document.getElementById("demo-prompt").value = randomPrompt;
      runDemo();
    }
  });
  document.getElementById("demo-reset").addEventListener("click", () => {
    state.demoSession = createDemoSession();
    runDemo();
  });

  runDemo();
}

function pickFeaturedPrompt(items) {
  const normalized = (items || []).map((item) =>
    typeof item === "string" ? { prompt: item, expected_decision: guessExpectedDecision(item) } : item
  );
  return normalized.find((item) => item.expected_decision === "block")?.prompt
    || normalized.find((item) => item.expected_decision === "warn")?.prompt
    || normalized[0]?.prompt
    || "";
}

function pickRandomPrompt(items, currentPrompt = "") {
  const prompts = (items || []).map((item) => (typeof item === "string" ? item : item.prompt)).filter(Boolean);
  if (!prompts.length) return "";
  const alternatives = prompts.filter((prompt) => prompt !== currentPrompt);
  const pool = alternatives.length ? alternatives : prompts;
  return pool[Math.floor(Math.random() * pool.length)] || "";
}

function renderHero(data) {
  const schemeTarget = document.getElementById("hero-scheme");
  schemeTarget.textContent = data.evaluation?.summary?.best_pr_auc_ovr?.model || "CatBoost";
}

function renderExamples(demo) {
  const target = document.getElementById("demo-examples");
  target.innerHTML = "";

  (demo.sample_prompts || []).forEach((item) => {
    const example = typeof item === "string"
      ? { title: "Сценарий", expected_decision: guessExpectedDecision(item), prompt: item }
      : item;
    const button = document.createElement("button");
    button.type = "button";
    button.className = `example-card tone-${example.expected_decision}`;
    button.innerHTML = `
      <div class="trace-head">
        <h3>${example.title}</h3>
        <span class="badge decision-${example.expected_decision}">${example.expected_decision}</span>
      </div>
      <p>${example.prompt}</p>
    `;
    button.addEventListener("click", () => {
      document.getElementById("demo-prompt").value = example.prompt;
      runDemo();
    });
    target.appendChild(button);
  });
}

function populateSelect(targetId, values) {
  const select = document.getElementById(targetId);
  select.innerHTML = values.map((value) => `<option value="${value}">${value}</option>`).join("");
}

function runDemo() {
  const demo = state.raw.demo || {};
  const policy = demo.policy || {};
  const prompt = document.getElementById("demo-prompt").value.trim();
  const clientId = (policy.allowed_clients || [])[0] || "agent-1";
  const transportType = document.getElementById("demo-transport").value || (policy.allowed_transports || [])[0];
  const interpretation = interpretPrompt(prompt, policy);
  renderInterpretation(interpretation);

  if (interpretation.status !== "supported") {
    renderIncompleteOrUnknown(prompt, clientId, transportType, interpretation);
    return;
  }

  const event = buildDemoEvent(prompt, clientId, transportType, policy, interpretation);
  const result = evaluateDemoEvent(event, policy, state.demoSession);
  updateDemoSession(event, result, state.demoSession);
  renderDemoResult(result, interpretation);
}

function buildMcpRequest(event) {
  return {
    jsonrpc: "2.0",
    id: "demo-tools-call",
    method: event.jsonrpc_method,
    params: {
      name: event.tool_name,
      arguments: event.params,
    },
  };
}

function buildDemoEvent(prompt, clientId, transportType, policy, interpretation) {
  return {
    prompt,
    client_id: clientId,
    transport_type: transportType,
    jsonrpc_method: "tools/call",
    tool_name: interpretation.tool_name,
    server_id: interpretation.server_id || policy.tool_server_map?.[interpretation.tool_name] || "filesystem-server",
    params: interpretation.arguments,
    payload_size: estimatePayloadSize(prompt, interpretation.arguments),
  };
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function escapeAttribute(value) {
  return String(value || "").replaceAll("\"", "&quot;");
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function evaluateDemoEvent(event, policy, session) {
  const requestFeatures = buildRequestFeatures(event, session, policy);
  const accessMatches = evaluateAccessControl(event, policy);
  const requestRuleMatches = evaluateRules(event, policy, session, {
    response_size: 0,
    response_time_ms: 0,
    is_error: false,
    error_code: "",
  });
  const earlyBlock = [...accessMatches, ...requestRuleMatches].some((match) => match.severity === "block");

  let backendResponse = null;
  let ruleMatches = [...accessMatches, ...requestRuleMatches];
  let responseAware = {
    response_size: 0,
    response_time_ms: 0,
    is_error: false,
    error_code: "",
  };

  if (!earlyBlock) {
    backendResponse = synthesizeBackendResponse(event);
    responseAware = {
      response_size: backendResponse.response_size,
      response_time_ms: backendResponse.response_time_ms,
      is_error: backendResponse.is_error,
      error_code: backendResponse.error_code,
    };
    ruleMatches = [...accessMatches, ...evaluateRules(event, policy, session, responseAware)];
  }

  const fullFeatures = buildFullFeatures(event, session, policy, responseAware);
  const riskExplanation = explainRiskScore(fullFeatures, session);
  const riskScore = riskExplanation.total;
  const mlClass = classifyMlOutcome(riskScore, policy);
  const decision = deriveDecision(riskScore, ruleMatches, policy);
  const decisionDriver = determineDecisionDriver(riskScore, ruleMatches, policy);
  const rationale = buildRationale(decision, riskScore, ruleMatches, policy);

  return {
    prompt: event.prompt,
    event,
    requestFeatures,
    features: fullFeatures,
    backendResponse,
    ruleMatches,
    riskScore,
    riskExplanation,
    mlClass,
    decision,
    decisionDriver,
    rationale,
    triggerHighlights: buildTriggerHighlights(event, policy, ruleMatches, fullFeatures),
    trace: buildTrace(event, requestFeatures, fullFeatures, ruleMatches, backendResponse, mlClass, riskScore, decision, decisionDriver, rationale),
  };
}

function buildTriggerHighlights(event, policy, ruleMatches, features) {
  const prompt = String(event.prompt || "");
  const requestText = JSON.stringify(buildMcpRequest(event), null, 2);
  const promptTriggers = [];
  const requestTriggers = [];
  const path = String(event.params.path || "");
  const url = String(event.params.url || "");

  (policy.sensitive_keywords || []).forEach((keyword) => {
    const regex = new RegExp(`\\b${escapeRegex(keyword)}\\b`, "ig");
    const promptMatches = prompt.match(regex) || [];
    const requestMatches = requestText.match(regex) || [];

    promptMatches.forEach((value) => {
      promptTriggers.push({
        text: value,
        tone: "ml",
        source: "ML keyword signal",
        reason: `Чувствительное слово "${value}" повышает риск.`,
      });
    });

    requestMatches.forEach((value) => {
      requestTriggers.push({
        text: value,
        tone: "ml",
        source: "ML keyword signal",
        reason: `Чувствительное слово "${value}" вошло в MCP-вызов.`,
      });
    });
  });

  ruleMatches.forEach((match) => {
    if (["sensitive_path_access", "private_backend_path_access", "path_outside_safe_roots"].includes(match.name) && path) {
      const trigger = {
        text: path,
        tone: match.severity,
        source: formatRuleName(match.name),
        reason: match.reason,
      };
      promptTriggers.push(trigger);
      requestTriggers.push(trigger);
    }

    if (match.name === "private_address_access" && url) {
      promptTriggers.push({
        text: extractHost(url) || url,
        tone: match.severity,
        source: formatRuleName(match.name),
        reason: match.reason,
      });
      requestTriggers.push({
        text: url,
        tone: match.severity,
        source: formatRuleName(match.name),
        reason: match.reason,
      });
    }
  });

  if (features.sensitive_path_flag && path) {
    const trigger = {
      text: path,
      tone: "rule",
      source: "sensitive_path_flag",
      reason: "Путь выглядел чувствительным для feature-слоя.",
    };
    promptTriggers.push(trigger);
    requestTriggers.push(trigger);
  }

  if (features.private_ip_flag && url) {
    promptTriggers.push({
      text: extractHost(url) || url,
      tone: "rule",
      source: "private_ip_flag",
      reason: "В запросе обнаружен приватный или служебный адрес.",
    });
    requestTriggers.push({
      text: url,
      tone: "rule",
      source: "private_ip_flag",
      reason: "В MCP-вызове обнаружен приватный или служебный адрес.",
    });
  }

  const dedupedPromptTriggers = dedupeTriggers(promptTriggers);
  const dedupedRequestTriggers = dedupeTriggers(requestTriggers);

  return {
    promptMarkup: dedupedPromptTriggers.length
      ? renderHighlightedText(prompt, dedupedPromptTriggers)
      : '<p class="highlight-empty">Явный текстовый триггер в пользовательском запросе не выделен.</p>',
    requestMarkup: dedupedRequestTriggers.length
      ? renderHighlightedText(requestText, dedupedRequestTriggers)
      : '<p class="highlight-empty">Явный текстовый триггер в MCP-вызове не выделен.</p>',
    legendMarkup: [...dedupedPromptTriggers, ...dedupedRequestTriggers].length
      ? renderTriggerLegend([...dedupedPromptTriggers, ...dedupedRequestTriggers])
      : '<p class="highlight-empty">Подсветка появляется для path, url, host и keyword-триггеров.</p>',
  };
}

function dedupeTriggers(triggers) {
  const seen = new Set();
  return triggers.filter((trigger) => {
    const key = `${trigger.text}::${trigger.source}::${trigger.tone}`;
    if (!trigger.text || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderHighlightedText(text, triggers) {
  const sortedTriggers = [...triggers].sort((left, right) => right.text.length - left.text.length);
  let workingText = String(text || "");
  const replacements = [];

  sortedTriggers.forEach((trigger, index) => {
    const regex = new RegExp(escapeRegex(trigger.text), "g");
    if (!regex.test(workingText)) return;
    const placeholder = `__TRIGGER_${index}__`;
    workingText = workingText.replace(regex, placeholder);
    replacements.push({
      placeholder,
      markup: `<mark class="trigger-mark tone-${normalizeTone(trigger.tone)}" title="${escapeAttribute(trigger.source)}: ${escapeAttribute(trigger.reason)}">${escapeHtml(trigger.text)}</mark>`,
    });
  });

  let html = escapeHtml(workingText);
  replacements.forEach(({ placeholder, markup }) => {
    html = html.replaceAll(placeholder, markup);
  });
  return `<pre class="highlight-code">${html}</pre>`;
}

function renderTriggerLegend(triggers) {
  return dedupeTriggers(triggers)
    .map(
      (trigger) => `
        <div class="trigger-chip tone-${normalizeTone(trigger.tone)}">
          <strong>${escapeHtml(trigger.text)}</strong>
          <span>${escapeHtml(trigger.source)}</span>
          <p>${escapeHtml(trigger.reason)}</p>
        </div>
      `
    )
    .join("");
}

function normalizeTone(value) {
  if (value === "block") return "block";
  if (value === "warn") return "warn";
  if (value === "rule") return "rule";
  return "ml";
}

function buildRequestFeatures(event, session, policy) {
  return {
    tool_name: event.tool_name,
    arg_count: Object.keys(event.params).length,
    payload_size: event.payload_size,
    transport_type: event.transport_type,
    tools_called_last_session: session.totalCalls,
    failed_calls_last_session: session.failedCalls,
    sensitive_path_flag: hasSensitivePath(event, policy),
    private_ip_flag: hasPrivateUrl(event),
    sensitive_keyword_flag: hasSensitiveKeywords(event, policy),
    repeated_tool_flag: event.tool_name === session.lastToolName,
  };
}

function buildFullFeatures(event, session, policy, responseAware) {
  return {
    ...buildRequestFeatures(event, session, policy),
    response_size: responseAware.response_size,
    response_time_ms: responseAware.response_time_ms,
    is_error: responseAware.is_error,
    external_url_flag: Object.values(event.params).some((value) => typeof value === "string" && value.startsWith("http")),
  };
}

function evaluateAccessControl(event, policy) {
  const matches = [];
  const allowedTransports = policy.allowed_transports || [];
  const allowlist = policy.client_tool_allowlist || {};
  const toolServerMap = policy.tool_server_map || {};

  if (!allowedTransports.includes(event.transport_type)) {
    matches.push({ name: "disallowed_transport", severity: "block", reason: `Транспорт ${event.transport_type} не разрешен политикой.` });
  }

  const allowedTools = allowlist[event.client_id];
  if (!allowedTools) {
    matches.push({ name: "unknown_client", severity: "block", reason: `Клиент ${event.client_id} не зарегистрирован в политике доступа.` });
  } else if (!allowedTools.includes(event.tool_name)) {
    matches.push({ name: "tool_not_allowed_for_client", severity: "block", reason: `Инструмент ${event.tool_name} не разрешен для клиента ${event.client_id}.` });
  }

  const expectedServer = toolServerMap[event.tool_name];
  if (expectedServer && event.server_id !== expectedServer) {
    matches.push({ name: "tool_server_mismatch", severity: "block", reason: `Инструмент ${event.tool_name} должен обращаться к ${expectedServer}, а не к ${event.server_id}.` });
  }

  return matches;
}

function evaluateRules(event, policy, session, responseAware) {
  const matches = [];
  const values = flattenParamValues(event.params);
  const lowerValues = values.map((value) => value.toLowerCase());

  if (event.payload_size > policy.max_payload_size) {
    matches.push({ name: "oversized_payload", severity: "warn", reason: "Размер запроса превышает настроенный порог." });
  }

  if ((responseAware.response_size || 0) > policy.max_response_size) {
    matches.push({ name: "oversized_response", severity: "warn", reason: "Размер ответа превышает настроенный порог." });
  }

  if (session.totalCalls >= policy.high_frequency_threshold) {
    matches.push({ name: "high_frequency_calls", severity: "warn", reason: "Частота вызовов в демонстрационной сессии превышает ожидаемый порог." });
  }

  const sensitiveFragment = lowerValues.find((value) => (policy.blocked_paths || []).some((blocked) => value.includes(blocked)));
  if (sensitiveFragment) {
    matches.push({ name: "sensitive_path_access", severity: "block", reason: `Обнаружен чувствительный путь: ${sensitiveFragment}.` });
  }

  const url = values.find((value) => value.startsWith("http://") || value.startsWith("https://"));
  if (url) {
    const host = extractHost(url);
    if ((policy.blocked_hosts || []).includes(host) || isPrivateHost(host)) {
      matches.push({ name: "private_address_access", severity: "block", reason: `Обнаружено обращение к приватному или служебному хосту: ${host}.` });
    }
  }

  if (event.tool_name === "filesystem.read_file") {
    const path = String(event.params.path || "");
    if (path && !(policy.safe_file_roots || []).some((root) => path.startsWith(root))) {
      matches.push({ name: "path_outside_safe_roots", severity: "warn", reason: "Операция чтения направлена на путь вне safe roots." });
    }
  }

  const path = String(event.params.path || "");
  if (path.startsWith("/private") && event.tool_name.includes("read")) {
    matches.push({ name: "private_backend_path_access", severity: "block", reason: "Попытка доступа к приватному backend-path через MCP." });
  }

  return deduplicateMatches(matches);
}

function deduplicateMatches(matches) {
  const seen = new Set();
  return matches.filter((match) => {
    if (seen.has(match.name)) return false;
    seen.add(match.name);
    return true;
  });
}

function synthesizeBackendResponse(event) {
  if (event.tool_name === "filesystem.read_file") {
    const path = String(event.params.path || "");
    return {
      response_size: path.includes("README") ? 2400 : 3600,
      response_time_ms: path.includes("README") ? 90 : 420,
      is_error: false,
      error_code: "",
      preview: `Содержимое ${path} успешно прочитано в пределах лабораторного backend API.`,
    };
  }

  if (event.tool_name === "filesystem.search") {
    const query = String(event.params.query || "");
    const broad = /\b(all|все|полный|full)\b/i.test(query);
    const sensitive = /\b(token|secret|password|credential|key)\b/i.test(query);
    return {
      response_size: broad || sensitive ? 8600 : 3100,
      response_time_ms: broad || sensitive ? 2480 : 430,
      is_error: false,
      error_code: "",
      preview: broad || sensitive
        ? "Поиск вернул расширенный набор совпадений, включая чувствительные фрагменты."
        : "Поиск завершен, найден ограниченный набор документов.",
    };
  }

  const url = String(event.params.url || "https://example.com");
  return {
    response_size: url.includes("docs") ? 3200 : 2100,
    response_time_ms: url.includes("docs") ? 460 : 230,
    is_error: false,
    error_code: "",
    preview: `HTTP-ответ получен от ${url}.`,
  };
}

function scoreRisk(features, session) {
  let score = 0.05;
  if (features.sensitive_path_flag) score += 0.45;
  if (features.private_ip_flag) score += 0.35;
  if (features.sensitive_keyword_flag) score += 0.2;
  if (features.repeated_tool_flag) score += 0.05;
  if (features.failed_calls_last_session >= 2) score += 0.1;
  if (features.payload_size > 8000) score += 0.1;
  if (features.response_time_ms > 2000) score += 0.1;
  if (session.sensitiveHits >= 1) score += 0.1;
  return Math.min(score, 1);
}

function explainRiskScore(features, session) {
  const contributions = [{ label: "base_score", value: 0.05 }];

  if (features.sensitive_path_flag) contributions.push({ label: "sensitive_path_flag", value: 0.45 });
  if (features.private_ip_flag) contributions.push({ label: "private_ip_flag", value: 0.35 });
  if (features.sensitive_keyword_flag) contributions.push({ label: "sensitive_keyword_flag", value: 0.2 });
  if (features.repeated_tool_flag) contributions.push({ label: "repeated_tool_flag", value: 0.05 });
  if (features.failed_calls_last_session >= 2) contributions.push({ label: "failed_calls_last_session >= 2", value: 0.1 });
  if (features.payload_size > 8000) contributions.push({ label: "payload_size > 8000", value: 0.1 });
  if (features.response_time_ms > 2000) contributions.push({ label: "response_time_ms > 2000", value: 0.1 });
  if (session.sensitiveHits >= 1) contributions.push({ label: "session_sensitive_hits >= 1", value: 0.1 });

  const rawTotal = contributions.reduce((sum, item) => sum + item.value, 0);
  return {
    baseScore: 0.05,
    contributions,
    total: Math.min(rawTotal, 1),
  };
}

function classifyMlOutcome(riskScore, policy) {
  if (riskScore >= policy.block_risk_threshold) return "malicious";
  if (riskScore >= policy.warn_risk_threshold) return "anomalous";
  return "normal";
}

function deriveDecision(riskScore, ruleMatches, policy) {
  if (ruleMatches.some((match) => match.severity === "block")) return "block";
  if (riskScore >= policy.block_risk_threshold) return "block";
  if (ruleMatches.some((match) => match.severity === "warn") || riskScore >= policy.warn_risk_threshold) return "warn";
  return "allow";
}

function buildRationale(decision, riskScore, ruleMatches, policy) {
  const blockMatches = ruleMatches.filter((match) => match.severity === "block");
  const warnMatches = ruleMatches.filter((match) => match.severity === "warn");

  if (blockMatches.length) return blockMatches.map((match) => match.reason).join("; ");
  if (decision === "block" && riskScore >= policy.block_risk_threshold) return "Оценка риска превысила порог block.";
  if (warnMatches.length) return warnMatches.map((match) => match.reason).join("; ");
  if (decision === "warn") return "Оценка риска превысила порог warn.";
  return "Блокирующие правила не сработали, итоговый риск остался в безопасной зоне.";
}

function determineDecisionDriver(riskScore, ruleMatches, policy) {
  const blockMatches = ruleMatches.filter((match) => match.severity === "block");
  const warnMatches = ruleMatches.filter((match) => match.severity === "warn");

  if (blockMatches.length) {
    return {
      source: "rule-based",
      label: "rule-based слой",
      detail: `сработало блокирующее правило: ${formatRuleName(blockMatches[0].name)}`,
    };
  }

  if (riskScore >= policy.block_risk_threshold) {
    return {
      source: "ml",
      label: "ML-модель",
      detail: "ML risk score превысил порог block",
    };
  }

  if (warnMatches.length) {
    return {
      source: "rule-based",
      label: "rule-based слой",
      detail: `сработало предупреждающее правило: ${formatRuleName(warnMatches[0].name)}`,
    };
  }

  if (riskScore >= policy.warn_risk_threshold) {
    return {
      source: "ml",
      label: "ML-модель",
      detail: "ML risk score превысил порог warn",
    };
  }

  return {
    source: "safe",
    label: "без эскалации",
    detail: "ни правила, ни ML-порог не потребовали эскалации",
  };
}

function buildTrace(event, requestFeatures, fullFeatures, ruleMatches, backendResponse, mlClass, riskScore, decision, decisionDriver, rationale) {
  const mcpRequest = buildMcpRequest(event);
  const trace = [
    {
      step: 1,
      title: "Сценарная интерпретация запроса",
      items: [
        `запрос: ${event.prompt}`,
        `выбранный инструмент: ${event.tool_name}`,
        `целевой MCP-сервер: ${event.server_id}`,
      ],
    },
    {
      step: 2,
      title: "Сформированный MCP-вызов",
      items: [
        `jsonrpc=${mcpRequest.jsonrpc}`,
        `method=${mcpRequest.method}`,
        `tool=${mcpRequest.params.name}`,
        `arguments=${JSON.stringify(mcpRequest.params.arguments)}`,
      ],
    },
    {
      step: 3,
      title: "Признаки запроса",
      items: [
        `payload_size=${requestFeatures.payload_size}`,
        `arg_count=${requestFeatures.arg_count}`,
        `sensitive_path=${requestFeatures.sensitive_path_flag}`,
        `private_ip=${requestFeatures.private_ip_flag}`,
        `sensitive_keyword=${requestFeatures.sensitive_keyword_flag}`,
      ],
    },
    {
      step: 4,
      title: "Проверки политики и правил",
      items: ruleMatches.length
        ? ruleMatches.map((match) => `${match.severity.toUpperCase()}: ${formatRuleName(match.name)}`)
        : ["Явные срабатывания правил и политики отсутствуют."],
    },
  ];

  trace.push(
    backendResponse
      ? {
          step: 5,
          title: "Анализ ответа",
          items: [
            `response_size=${fullFeatures.response_size}`,
            `response_time_ms=${fullFeatures.response_time_ms}`,
            `preview: ${backendResponse.preview}`,
          ],
        }
      : {
          step: 5,
          title: "Анализ ответа",
          items: ["Сработала ранняя блокировка: backend-ответ отсутствует."],
        }
  );

  trace.push({
    step: 6,
    title: "Оценка риска и итоговое решение",
    tone: decision,
    items: [
      `ml-класс: ${mlClass}`,
      `risk_score=${riskScore.toFixed(2)}`,
      `источник решения: ${decisionDriver.label}`,
      decisionDriver.detail,
      `решение=${decision}`,
      rationale,
    ],
  });

  return trace;
}

function updateDemoSession(event, result, session) {
  session.totalCalls += 1;
  if (result.backendResponse?.is_error) session.failedCalls += 1;
  if (event.tool_name) session.lastToolName = event.tool_name;
  if (result.features.sensitive_path_flag || result.features.private_ip_flag) session.sensitiveHits += 1;
}

function renderDemoResult(result, interpretation) {
  const requestPreview = document.getElementById("demo-request-preview");
  requestPreview.textContent = JSON.stringify(buildMcpRequest(result.event), null, 2);
  const primaryRule = result.ruleMatches.find((match) => match.severity === "block") || result.ruleMatches[0] || null;
  const ruleTitle =
    result.decisionDriver.source === "rule-based"
      ? primaryRule?.severity === "block"
        ? "Блокирующее правило"
        : "Предупреждающее правило"
      : "Что сработало";
  const ruleValue =
    result.decisionDriver.source === "rule-based"
      ? formatRuleName(primaryRule?.name || result.decisionDriver.detail)
      : result.decisionDriver.detail;

  const summary = document.getElementById("demo-summary");
  summary.innerHTML = `
    <div class="summary-card">
      <span>Намерение</span>
      <strong>${interpretation.intent}</strong>
    </div>
    <div class="summary-card">
      <span>Инструмент</span>
      <strong>${result.event.tool_name}</strong>
    </div>
    <div class="summary-card">
      <span>JSON-RPC method</span>
      <strong>${result.event.jsonrpc_method}</strong>
    </div>
    <div class="summary-card">
      <span>ML-оценка риска</span>
      <strong>${result.riskScore.toFixed(2)}</strong>
    </div>
    <div class="summary-card">
      <span>ML-сигнал</span>
      <strong>${formatMlSignal(result.mlClass, result.riskScore)}</strong>
    </div>
    <div class="summary-card">
      <span>Источник решения</span>
      <strong>${result.decisionDriver.label}</strong>
    </div>
    <div class="summary-card">
      <span>${ruleTitle}</span>
      <strong>${ruleValue}</strong>
    </div>
    <div class="summary-card">
      <span>Итоговое решение</span>
      <strong><span class="badge decision-${result.decision}">${result.decision}</span></strong>
    </div>
  `;

  renderCaseFlow(result, interpretation);
  renderDecisionLadder(result, state.raw.demo?.policy || {});

  const response = document.getElementById("demo-response");
  response.innerHTML = `
    <div class="response-grid">
      <div class="response-card">
        <span>Краткое объяснение</span>
        <strong>${result.decisionDriver.label} / ${result.decision}</strong>
        <div>${result.rationale}</div>
        <div style="margin-top:12px;">ML-оценка риска: ${result.riskScore.toFixed(2)}; ML-вердикт: ${result.mlClass}.</div>
        <div style="margin-top:8px;">Что определило решение: ${result.decisionDriver.detail}.</div>
        ${
          result.backendResponse
            ? `<div style="margin-top:12px;">Ответ backend: ${result.backendResponse.preview}</div>`
            : `<div style="margin-top:12px;">Вызов был остановлен до обращения к MCP-серверу и backend.</div>`
        }
      </div>
      <div class="response-card">
        <span>Локальное объяснение решения</span>
        <strong>Какие признаки и правила сработали</strong>
        <div class="explanation-block">
          <div class="explanation-title">Rule-based слой</div>
          ${
            result.ruleMatches.length
              ? `<ul class="explanation-list">${result.ruleMatches
                  .map((match) => `<li><strong>${match.severity}</strong>: ${formatRuleName(match.name)} — ${match.reason}</li>`)
                  .join("")}</ul>`
              : `<div class="explanation-empty">Явные rule-based срабатывания отсутствуют.</div>`
          }
        </div>
        <div class="explanation-block">
          <div class="explanation-title">ML-оценка риска</div>
          <ul class="explanation-list">
            ${result.riskExplanation.contributions
              .map((item) => `<li>${item.label}: +${Number(item.value).toFixed(2)}</li>`)
              .join("")}
          </ul>
          <div class="explanation-total">Итоговый risk score: ${result.riskExplanation.total.toFixed(2)}</div>
        </div>
      </div>
    </div>
  `;

  document.getElementById("prompt-highlight").innerHTML = result.triggerHighlights.promptMarkup;
  document.getElementById("request-highlight").innerHTML = result.triggerHighlights.requestMarkup;
  document.getElementById("trigger-legend").innerHTML = result.triggerHighlights.legendMarkup;

  const trace = document.getElementById("demo-trace");
  if (!trace) return;
  trace.innerHTML = result.trace
    .map(
      (step) => `
        <div class="trace-card">
          <div class="trace-head">
            <strong>${step.step}. ${step.title}</strong>
            ${step.tone ? `<span class="badge decision-${step.tone}">${step.tone}</span>` : ""}
          </div>
          <ul>${step.items.map((item) => `<li>${item}</li>`).join("")}</ul>
        </div>
      `
    )
    .join("");
}

function renderInterpretation(interpretation) {
  const preview = document.getElementById("demo-interpretation-preview");
  const status = document.getElementById("demo-interpretation-status");

  status.textContent = formatInterpretationStatus(interpretation.status);
  status.className = `interpretation-status status-${interpretation.status}`;

  preview.textContent = JSON.stringify(
    {
      status: interpretation.status,
      intent: interpretation.intent,
      confidence: interpretation.confidence,
      tool_name: interpretation.tool_name || null,
      arguments: interpretation.arguments || null,
      missing: interpretation.missing || [],
      message: interpretation.message,
    },
    null,
    2
  );
}

function renderIncompleteOrUnknown(prompt, clientId, transportType, interpretation) {
  const requestPreview = document.getElementById("demo-request-preview");
  requestPreview.textContent = JSON.stringify(
    {
      status: interpretation.status,
      message: interpretation.message,
      mcp_request: null,
    },
    null,
    2
  );

  const summary = document.getElementById("demo-summary");
  summary.innerHTML = `
    <div class="summary-card">
      <span>Намерение</span>
      <strong>${interpretation.intent}</strong>
    </div>
    <div class="summary-card">
      <span>Транспорт</span>
      <strong>${transportType}</strong>
    </div>
    <div class="summary-card">
      <span>Итоговое решение</span>
      <strong><span class="badge decision-warn">не запущено</span></strong>
    </div>
    <div class="summary-card">
      <span>Причина остановки</span>
      <strong>${formatInterpretationStatus(interpretation.status)}</strong>
    </div>
  `;

  renderCaseFlow(null, interpretation);
  renderDecisionLadder(
    {
      decision: "warn",
      riskScore: null,
      mlClass: null,
      decisionDriver: { source: "none", detail: "Остановка до запуска firewall" },
      ruleMatches: [],
    },
    state.raw.demo?.policy || {},
    "Остановка до запуска firewall"
  );

  const response = document.getElementById("demo-response");
  response.innerHTML = `
    <div class="response-grid">
      <div class="response-card">
        <span>Краткое объяснение</span>
        <strong>${interpretation.message}</strong>
        <div>Firewall-анализ не запускался, поскольку локальный интерпретатор не смог построить корректный MCP tools/call для запроса: ${prompt || "пустой ввод"}.</div>
      </div>
      <div class="response-card">
        <span>Локальное объяснение решения</span>
        <strong>Недоступно для текущего ввода</strong>
        <div>Пояснение по признакам и rule-based срабатываниям строится только после формирования валидного MCP-вызова и запуска защитного контура.</div>
      </div>
    </div>
  `;

  document.getElementById("prompt-highlight").innerHTML = `<pre class="highlight-code">${escapeHtml(prompt || "пустой ввод")}</pre>`;
  document.getElementById("request-highlight").innerHTML = '<p class="highlight-empty">MCP-вызов не был сформирован.</p>';
  document.getElementById("trigger-legend").innerHTML = '<p class="highlight-empty">Подсветка появится после успешной интерпретации запроса в tools/call.</p>';

  const trace = document.getElementById("demo-trace");
  if (!trace) return;
  trace.innerHTML = [
    {
      step: 1,
      title: "Сценарная интерпретация запроса",
      items: [
        `запрос: ${prompt || "пустой ввод"}`,
        `намерение: ${interpretation.intent}`,
        `статус: ${formatInterpretationStatus(interpretation.status)}`,
        interpretation.message,
      ],
    },
    {
      step: 2,
      title: "Формирование MCP-вызова",
      tone: "warn",
      items: [
        "Корректный MCP tools/call не сформирован.",
        interpretation.missing?.length
          ? `Недостающие аргументы: ${interpretation.missing.join(", ")}`
          : "Запрос находится вне поддерживаемых демонстрационных сценариев.",
      ],
    },
    {
      step: 3,
      title: "Анализ firewall",
      items: ["Разбор остановлен до этапа policy/rule/ML, так как валидный MCP-вызов отсутствует."],
    },
  ]
    .map(
      (step) => `
        <div class="trace-card">
          <div class="trace-head">
            <strong>${step.step}. ${step.title}</strong>
            ${step.tone ? `<span class="badge decision-${step.tone}">${step.tone}</span>` : ""}
          </div>
          <ul>${step.items.map((item) => `<li>${item}</li>`).join("")}</ul>
        </div>
      `
    )
    .join("");
}

function renderDecisionLadder(result, policy, captionOverride = "") {
  const target = document.getElementById("decision-ladder");
  const warnThreshold = Number(policy.warn_risk_threshold ?? 0.4);
  const blockThreshold = Number(policy.block_risk_threshold ?? 0.75);
  const decision = result?.decision || "warn";
  const numericRisk = Number.isFinite(Number(result?.riskScore)) ? Number(result.riskScore) : null;
  const markerLeft = numericRisk === null ? 0 : Math.max(0, Math.min(100, numericRisk * 100));
  const source = result?.decisionDriver?.source || "none";
  const sourceDetail = result?.decisionDriver?.detail || "";
  const mlZone = numericRisk === null ? null : numericRisk >= blockThreshold ? "block" : numericRisk >= warnThreshold ? "warn" : "allow";
  const isRuleBasedDecision = source === "rule-based";
  const hasRuleOverride = isRuleBasedDecision && decision !== mlZone;
  const zoneLabels = hasRuleOverride
    ? {
        allow: { title: "низкий ML риск", subtitle: `ниже ${warnThreshold.toFixed(2)}` },
        warn: { title: "средний ML риск", subtitle: `${warnThreshold.toFixed(2)} – ${blockThreshold.toFixed(2)}` },
        block: { title: "высокий ML риск", subtitle: `выше ${blockThreshold.toFixed(2)}` },
      }
    : {
        allow: { title: "allow", subtitle: `ниже ${warnThreshold.toFixed(2)}` },
        warn: { title: "warn", subtitle: `${warnThreshold.toFixed(2)} – ${blockThreshold.toFixed(2)}` },
        block: { title: "block", subtitle: `выше ${blockThreshold.toFixed(2)}` },
      };
  let autoSummary = "Решение не рассчитывалось по risk score.";

  if (numericRisk !== null) {
    const base =
      numericRisk < warnThreshold
        ? `ML risk score ${numericRisk.toFixed(2)} остался ниже порога warn ${warnThreshold.toFixed(2)}.`
        : numericRisk >= blockThreshold
          ? `ML risk score ${numericRisk.toFixed(2)} превысил порог block ${blockThreshold.toFixed(2)}.`
          : `ML risk score ${numericRisk.toFixed(2)} расположен между порогами warn ${warnThreshold.toFixed(2)} и block ${blockThreshold.toFixed(2)}.`;
    autoSummary =
      hasRuleOverride
        ? `${base} Итоговое решение вынесено отдельно rule-based слоем: ${sourceDetail}.`
        : base;
  }

  const summaryText =
    captionOverride || autoSummary;

  if (isRuleBasedDecision) {
    target.innerHTML = `
      <div class="ladder-head">
        <strong>Как читать это решение</strong>
        <span>В этом кейсе итог принят rule-based слоем. ML-сигнал показан только как вспомогательный контекст и не определяет финальный вердикт.</span>
      </div>
      <div class="decision-compact">
        <article class="decision-compact-card">
          <span>ML signal</span>
          <strong>${formatMlSignal(result.mlClass, result.riskScore)}</strong>
          <p>${numericRisk === null ? "ML-оценка риска не рассчитывалась." : `ML risk score: ${numericRisk.toFixed(2)}.`}</p>
        </article>
        <article class="decision-compact-card is-primary">
          <span>Final rule-based decision</span>
          <strong><span class="badge decision-${decision}">${decision}</span></strong>
          <p>${sourceDetail}</p>
        </article>
      </div>
    `;
    return;
  }

  target.innerHTML = `
    <div class="ladder-head">
      <strong>${hasRuleOverride ? "Вспомогательная шкала ML-риска" : "Шкала ML-оценки риска"}</strong>
      <span>${summaryText}</span>
    </div>
    ${
      hasRuleOverride
        ? `<div class="ladder-override">
            <span class="ladder-override-label">Rule-based override</span>
            <strong>Финальное решение: <span class="badge decision-${decision}">${decision}</span></strong>
            <p>В этом кейсе ML-порог не определяет финал. Итоговый вердикт принят policy/rule-based слоем: ${sourceDetail}.</p>
          </div>`
        : ""
    }
    <div class="ladder-track">
      <div class="ladder-zone zone-allow${mlZone === "allow" ? " is-active" : ""}">
        <strong>${zoneLabels.allow.title}</strong>
        <span>${zoneLabels.allow.subtitle}</span>
      </div>
      <div class="ladder-zone zone-warn${mlZone === "warn" ? " is-active" : ""}">
        <strong>${zoneLabels.warn.title}</strong>
        <span>${zoneLabels.warn.subtitle}</span>
      </div>
      <div class="ladder-zone zone-block${mlZone === "block" ? " is-active" : ""}">
        <strong>${zoneLabels.block.title}</strong>
        <span>${zoneLabels.block.subtitle}</span>
      </div>
      ${
        numericRisk === null
          ? ""
          : `<div class="ladder-marker decision-${decision}" style="left:${markerLeft}%;">
              <span>${numericRisk.toFixed(2)}</span>
            </div>`
      }
    </div>
  `;
}

function renderCaseFlow(result, interpretation) {
  const target = document.getElementById("case-flow");
  const steps = result
    ? [
        {
          title: "Prompt",
          value: truncateText(result.prompt, 56),
          tone: "neutral",
        },
        {
          title: "Intent",
          value: interpretation.intent || "unknown",
          tone: "neutral",
        },
        {
          title: "MCP tool",
          value: result.event.tool_name,
          tone: "neutral",
        },
        {
          title: "Decision",
          value: result.decision,
          tone: result.decision,
        },
      ]
    : [
        {
          title: "Prompt",
          value: "вне поддержанного сценария",
          tone: "warn",
        },
        {
          title: "Intent",
          value: interpretation.intent || "unknown",
          tone: "warn",
        },
        {
          title: "MCP tool",
          value: "не сформирован",
          tone: "warn",
        },
        {
          title: "Decision",
          value: "не запущено",
          tone: "warn",
        },
      ];

  target.innerHTML = `
    <div class="case-flow-head">
      <strong>Схема текущего кейса</strong>
      <span>${result ? "Быстрый маршрут от текста к итоговому решению." : "Сценарий остановился до запуска firewall."}</span>
    </div>
    <div class="case-flow-track">
      ${steps
        .map(
          (step, index) => `
            <article class="case-flow-step tone-${step.tone}">
              <span class="case-flow-index">0${index + 1}</span>
              <strong>${step.title}</strong>
              <p>${escapeHtml(step.value)}</p>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function formatMlSignal(mlClass, riskScore) {
  const numericRisk = Number(riskScore);
  if (!Number.isFinite(numericRisk)) return mlClass || "n/a";
  if (numericRisk < 0.4) return `low risk (${numericRisk.toFixed(2)})`;
  if (numericRisk < 0.75) return `elevated risk (${numericRisk.toFixed(2)})`;
  return `high risk (${numericRisk.toFixed(2)})`;
}

function truncateText(value, limit = 56) {
  const text = String(value || "");
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

function estimatePayloadSize(prompt, params) {
  return Math.max(
    220,
    prompt.length * 18 + Object.values(params).reduce((sum, value) => sum + String(value).length * 6, 0)
  );
}

function extractPath(text) {
  const normalized = normalizeWhitespace(text);
  const candidates = [
    normalized.match(/["'](\/[^"'\s,;]+|\.\.?\/[^"'\s,;]+|\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)["']/),
    normalized.match(/(\/[^\s,;]+)/),
    normalized.match(/\b(?:файл|файла|путь|path|file)\s+((?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)/i),
    normalized.match(/\b((?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)\b/),
  ];

  for (const match of candidates) {
    const candidate = match?.[1] || match?.[0] || "";
    const normalizedPath = normalizePathCandidate(candidate);
    if (normalizedPath) return normalizedPath;
  }

  return "";
}

function extractUrl(text) {
  const explicit = text.match(/https?:\/\/[^\s)]+/i);
  if (explicit) return explicit[0];

  const bare = text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s,;]*)?/i);
  if (bare) {
    const candidate = bare[0];
    return /^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
  }

  return "";
}

function cleanupSearchQuery(prompt) {
  return normalizeWhitespace(
    prompt
      .replace(/^(найди|выполни поиск|поиск|search for|search)\s*/i, "")
      .replace(/\b(?:в|inside|within)\s+(\/[^\s,;]+|(?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)\b/gi, "")
      .replace(/\b(?:файл|путь|path|file)\b/gi, "")
  ) || prompt;
}

function interpretPrompt(prompt, policy) {
  const normalizedPrompt = normalizeWhitespace(prompt);
  const lower = normalizedPrompt.toLowerCase();
  const path = extractPath(normalizedPrompt);
  const url = extractUrl(normalizedPrompt);

  if (!normalizedPrompt) {
    return {
      status: "unknown",
      intent: "unknown",
      confidence: 0,
      message: "Пустой запрос не может быть интерпретирован как MCP-сценарий.",
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
    message: "Запрос находится вне поддерживаемых демонстрационных сценариев. Demo интерпретирует чтение файла, web-fetch и поиск.",
  };
}

function detectPromptIntent(prompt, context = {}) {
  const lower = prompt.toLowerCase();

  if (context.url) return "fetch";
  if (hasReadIntent(lower, context.path)) return "read";
  if (hasFetchIntent(lower)) return "fetch";
  return "search";
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
  return /(найди|ищи|поиск|search|find|grep|поищи|проверь.*(секрет|token|password|key))/i.test(lower);
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

function guessExpectedDecision(prompt) {
  const lower = prompt.toLowerCase();
  if (lower.includes("/private") || lower.includes("169.254.169.254")) return "block";
  if (lower.includes("token") || lower.includes("secret") || lower.includes("password")) return "warn";
  return "allow";
}

function flattenParamValues(value) {
  if (Array.isArray(value)) return value.flatMap(flattenParamValues);
  if (value && typeof value === "object") return Object.values(value).flatMap(flattenParamValues);
  return [String(value)];
}

function hasSensitivePath(event, policy) {
  const values = flattenParamValues(event.params).map((value) => value.toLowerCase());
  return values.some((value) => (policy.blocked_paths || []).some((blocked) => value.includes(blocked)));
}

function hasPrivateUrl(event) {
  return flattenParamValues(event.params)
    .filter((value) => value.startsWith("http://") || value.startsWith("https://"))
    .some((value) => isPrivateHost(extractHost(value)));
}

function hasSensitiveKeywords(event, policy) {
  const joined = flattenParamValues(event.params).join(" ").toLowerCase();
  return (policy.sensitive_keywords || []).some((keyword) => joined.includes(keyword));
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
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "169.254.169.254" ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)
  );
}

function formatRuleName(value) {
  return {
    disallowed_transport: "disallowed_transport",
    unknown_client: "unknown_client",
    tool_not_allowed_for_client: "tool_not_allowed_for_client",
    tool_server_mismatch: "tool_server_mismatch",
    sensitive_path_access: "sensitive_path_access",
    private_address_access: "private_address_access",
    path_outside_safe_roots: "path_outside_safe_roots",
    private_backend_path_access: "private_backend_path_access",
    oversized_payload: "oversized_payload",
    oversized_response: "oversized_response",
    high_frequency_calls: "high_frequency_calls",
  }[value] || value;
}

function formatInterpretationStatus(value) {
  return {
    supported: "готов к разбору",
    incomplete: "недостаточно данных",
    unknown: "вне сценария",
  }[value] || value;
}

document.addEventListener("DOMContentLoaded", init);
