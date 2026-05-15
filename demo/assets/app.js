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
  const response = await fetch("/mcp-firewall-site/demo/data/dashboard.json");
  const data = await response.json();
  state.raw = data;

  renderHero(data);
  renderExamples(data.demo || {});
  renderPolicy(data.demo?.policy || {});
  populateSelect("demo-client", data.demo?.policy?.allowed_clients || []);
  populateSelect("demo-transport", data.demo?.policy?.allowed_transports || []);

  document.getElementById("demo-run").addEventListener("click", runDemo);
  document.getElementById("demo-reset").addEventListener("click", () => {
    state.demoSession = createDemoSession();
    runDemo();
  });

  runDemo();
}

function renderHero(data) {
  const schemeTarget = document.getElementById("hero-scheme");
  schemeTarget.textContent = data.evaluation?.summary?.best_macro_f1?.model || "HistGradientBoosting";
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

function renderPolicy(policy) {
  const target = document.getElementById("policy-card");
  target.innerHTML = `
    <div class="policy-grid">
      <div class="policy-line"><span>Разрешенные транспорты</span><strong>${(policy.allowed_transports || []).join(", ")}</strong></div>
      <div class="policy-line"><span>Разрешенные клиенты</span><strong>${(policy.allowed_clients || []).join(", ")}</strong></div>
      <div class="policy-line"><span>Безопасные файловые корни</span><strong>${(policy.safe_file_roots || []).join(", ")}</strong></div>
      <div class="policy-line"><span>Заблокированные хосты</span><strong>${(policy.blocked_hosts || []).join(", ")}</strong></div>
      <div class="policy-line"><span>Лимиты запроса / ответа</span><strong>${policy.max_payload_size} / ${policy.max_response_size}</strong></div>
      <div class="policy-line"><span>Пороги warn / block</span><strong>${policy.warn_risk_threshold} / ${policy.block_risk_threshold}</strong></div>
      <div class="policy-line"><span>Порог частоты вызовов</span><strong>${policy.high_frequency_threshold}</strong></div>
    </div>
  `;
}

function populateSelect(targetId, values) {
  const select = document.getElementById(targetId);
  select.innerHTML = values.map((value) => `<option value="${value}">${value}</option>`).join("");
}

function runDemo() {
  const demo = state.raw.demo || {};
  const policy = demo.policy || {};
  const prompt = document.getElementById("demo-prompt").value.trim();
  const clientId = document.getElementById("demo-client").value || (policy.allowed_clients || [])[0];
  const transportType = document.getElementById("demo-transport").value || (policy.allowed_transports || [])[0];
  const event = buildDemoEvent(prompt, clientId, transportType, policy);
  const result = evaluateDemoEvent(event, policy, state.demoSession);
  updateDemoSession(event, result, state.demoSession);
  renderDemoResult(result);
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

function buildDemoEvent(prompt, clientId, transportType, policy) {
  const lower = prompt.toLowerCase();
  const path = extractPath(prompt);
  const url = extractUrl(prompt);
  let toolName = "filesystem.search";
  let params = { path: "/workspace", query: prompt };
  let serverId = "filesystem-server";

  if (url || lower.includes("http") || lower.includes("открой")) {
    toolName = "web.fetch";
    params = { url: url || "https://example.com" };
    serverId = policy.tool_server_map?.[toolName] || "http-server";
  } else if (lower.includes("прочитай") || lower.includes("открой файл") || lower.includes("read")) {
    toolName = "filesystem.read_file";
    params = { path: path || "/workspace/project/README.md" };
    serverId = policy.tool_server_map?.[toolName] || "filesystem-server";
  } else {
    toolName = "filesystem.search";
    params = {
      path: path || "/workspace/project",
      query: cleanupSearchQuery(prompt),
    };
    serverId = policy.tool_server_map?.[toolName] || "filesystem-server";
  }

  return {
    prompt,
    client_id: clientId,
    transport_type: transportType,
    jsonrpc_method: "tools/call",
    tool_name: toolName,
    server_id: serverId,
    params,
    payload_size: estimatePayloadSize(prompt, params),
  };
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
  const riskScore = scoreRisk(fullFeatures, session);
  const mlClass = classifyMlOutcome(riskScore, ruleMatches, fullFeatures, policy);
  const decision = deriveDecision(riskScore, ruleMatches, policy);
  const rationale = buildRationale(decision, riskScore, ruleMatches, policy);

  return {
    prompt: event.prompt,
    event,
    requestFeatures,
    features: fullFeatures,
    backendResponse,
    ruleMatches,
    riskScore,
    mlClass,
    decision,
    rationale,
    trace: buildTrace(event, requestFeatures, fullFeatures, ruleMatches, backendResponse, mlClass, riskScore, decision, rationale),
  };
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

function classifyMlOutcome(riskScore, ruleMatches, features, policy) {
  if (ruleMatches.some((match) => match.severity === "block") || features.private_ip_flag || features.sensitive_path_flag) {
    return "malicious";
  }
  if (ruleMatches.some((match) => match.severity === "warn") || riskScore >= policy.warn_risk_threshold) {
    return "anomalous";
  }
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

function buildTrace(event, requestFeatures, fullFeatures, ruleMatches, backendResponse, mlClass, riskScore, decision, rationale) {
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
      `класс оценочного слоя: ${mlClass}`,
      `risk_score=${riskScore.toFixed(2)}`,
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

function renderDemoResult(result) {
  const requestPreview = document.getElementById("demo-request-preview");
  requestPreview.textContent = JSON.stringify(buildMcpRequest(result.event), null, 2);

  const summary = document.getElementById("demo-summary");
  summary.innerHTML = `
    <div class="summary-card">
      <span>Режим интерпретации</span>
      <strong>локальный сценарный разбор</strong>
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
      <span>Оценочный слой</span>
      <strong>${result.mlClass}</strong>
    </div>
    <div class="summary-card">
      <span>Итоговое решение</span>
      <strong><span class="badge decision-${result.decision}">${result.decision}</span></strong>
    </div>
  `;

  const response = document.getElementById("demo-response");
  response.innerHTML = `
    <div class="response-card">
      <span>Краткое объяснение</span>
      <strong>${result.mlClass} / ${result.decision}</strong>
      <div>${result.rationale}</div>
      ${
        result.backendResponse
          ? `<div style="margin-top:12px;">Ответ backend: ${result.backendResponse.preview}</div>`
          : `<div style="margin-top:12px;">Вызов был остановлен до обращения к MCP-серверу и backend.</div>`
      }
    </div>
  `;

  const trace = document.getElementById("demo-trace");
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

function estimatePayloadSize(prompt, params) {
  return Math.max(
    220,
    prompt.length * 18 + Object.values(params).reduce((sum, value) => sum + String(value).length * 6, 0)
  );
}

function extractPath(text) {
  const match = text.match(/(\/[^\s,;]+)/);
  return match ? match[1] : "";
}

function extractUrl(text) {
  const match = text.match(/https?:\/\/[^\s]+/i);
  return match ? match[0] : "";
}

function cleanupSearchQuery(prompt) {
  return prompt.replace(/^найди/i, "").replace(/^выполни поиск/i, "").trim() || prompt;
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

document.addEventListener("DOMContentLoaded", init);
