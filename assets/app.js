const COLORS = {
  normal: "#2f7554",
  malicious: "#9c2f21",
  anomalous: "#b47919",
  allow: "#2f7554",
  warn: "#b47919",
  block: "#9c2f21",
};

const state = {
  raw: null,
  filteredEvents: [],
  filters: {
    label: "all",
    decision: "all",
    tool: "all",
  },
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
  const response = await fetch("/mcp-firewall-site/data/dashboard.json");
  const data = await response.json();
  state.raw = data;
  state.filteredEvents = data.events.slice();

  renderHero(data);
  renderKpis(data);
  renderBarChart("labels-chart", data.summary.label_counts, "label");
  renderBarChart("decisions-chart", data.summary.decision_counts, "decision");
  renderScenarioGrid(data.summary.scenario_matrix);
  renderEvaluation(data.evaluation || {});
  renderFilters(data.events);
  applyFilters();
}

function renderHero(data) {
  const schemeTarget = document.getElementById("hero-scheme");
  if (schemeTarget) {
    schemeTarget.textContent =
      data.evaluation?.summary?.best_macro_f1?.model || data.evaluation?.summary?.current_scheme || "HistGradientBoosting";
  }
}

function renderKpis(data) {
  const grid = document.getElementById("kpi-grid");
  const template = document.getElementById("kpi-card-template");
  const summary = data.summary;
  const total = data.meta.total_records;
  const blocked = summary.decision_counts.block || 0;
  const warned = summary.decision_counts.warn || 0;
  const anomalousShare = summary.metrics_by_label.anomalous?.share || 0;
  const cards = [
    {
      label: "Всего событий",
      value: total,
      note: "Количество событий в сформированном лабораторном датасете.",
    },
    {
      label: "События с block",
      value: blocked,
      note: "Число событий, завершившихся итоговым решением block.",
    },
    {
      label: "События с warn",
      value: warned,
      note: "Число событий с промежуточным решением warn.",
    },
    {
      label: "Доля anomalous",
      value: `${Math.round(anomalousShare * 100)}%`,
      note: "Доля аномальных сценариев в лабораторной выборке.",
    },
  ];

  grid.innerHTML = "";
  cards.forEach((card) => {
    const fragment = template.content.cloneNode(true);
    fragment.querySelector(".kpi-label").textContent = card.label;
    fragment.querySelector(".kpi-value").textContent = card.value;
    fragment.querySelector(".kpi-note").textContent = card.note;
    grid.appendChild(fragment);
  });
}

function renderBarChart(targetId, counts, type) {
  const target = document.getElementById(targetId);
  const entries = Object.entries(counts);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  const max = Math.max(...entries.map(([, count]) => count), 1);

  target.innerHTML = "";
  entries.forEach(([key, count]) => {
    const row = document.createElement("div");
    row.className = "bar-row";
    const share = total ? ((count / total) * 100).toFixed(1) : "0.0";
    row.innerHTML = `
      <div class="bar-meta">
        <strong>${formatCategoryName(key, type)}</strong>
        <span>${count} (${share}%)</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(count / max) * 100}%; background: linear-gradient(90deg, ${pickColor(key, type)}, rgba(214,164,59,0.9));"></div>
      </div>
    `;
    target.appendChild(row);
  });
}

function renderScenarioGrid(matrix) {
  const target = document.getElementById("scenario-grid");
  target.innerHTML = "";
  Object.entries(matrix).forEach(([label, scenarios]) => {
    Object.entries(scenarios).forEach(([scenario, count]) => {
      const article = document.createElement("article");
      article.className = "scenario-card";
      article.innerHTML = `
        <h4>${formatScenarioName(scenario)}</h4>
        <p><span class="badge label-${label}">${formatCategoryName(label, "label")}</span></p>
        <p>${count} событий этого типа.</p>
      `;
      target.appendChild(article);
    });
  });
}

function renderEvaluation(evaluation) {
  renderSplitProtocol(evaluation.protocol || {});
  renderEvaluationSummary(evaluation.summary || {});
  renderModelLeaderboard(evaluation.model_metrics || []);
  renderConfusionMatrix(evaluation.model_metrics || [], evaluation.summary || {});
  renderScenarioErrors(evaluation.error_analysis || [], evaluation.summary || {});
  renderOverfittingGap(evaluation.overfitting || [], evaluation.summary || {});
  renderModelMetrics(evaluation.model_metrics || []);
  renderFeatureImportance(evaluation.feature_importance || []);
  renderPerformanceTable(evaluation.performance || []);
}

function renderSplitProtocol(protocol) {
  const target = document.getElementById("split-protocol");
  if (!Object.keys(protocol).length) {
    target.innerHTML = '<p class="chart-empty">Описание split protocol пока не загружено.</p>';
    return;
  }

  const rows = [
    { label: "Основной split", value: protocol.type || "n/a" },
    { label: "Всего групп", value: protocol.groups_total },
    { label: "Train groups", value: protocol.train_groups },
    { label: "Test groups", value: protocol.test_groups },
    { label: "Train rows", value: protocol.train_rows },
    { label: "Test rows", value: protocol.test_rows },
  ].filter((item) => item.value);
  target.innerHTML = `
    <div class="meta-table-wrap">
      <table class="meta-table">
        <tbody>
          ${rows
            .map(
              (item) => `
                <tr>
                  <th>${item.label}</th>
                  <td>${item.value}</td>
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </div>
    <div class="distribution-grid">
      ${renderDistributionCard("Train распределение", protocol.train_label_distribution)}
      ${renderDistributionCard("Test распределение", protocol.test_label_distribution)}
    </div>
  `;
}

function renderEvaluationSummary(summary) {
  const target = document.getElementById("evaluation-summary");
  const rows = [
    {
      label: "Лучшая ML-модель по macro F1",
      model: summary.best_macro_f1?.model,
      value: summary.best_macro_f1 ? Number(summary.best_macro_f1.value).toFixed(4) : null,
    },
    {
      label: "Лучшая ML-модель по accuracy",
      model: summary.best_accuracy?.model,
      value: summary.best_accuracy ? Number(summary.best_accuracy.value).toFixed(4) : null,
    },
    {
      label: "Лучшая ML-модель по ROC-AUC OVR",
      model: summary.best_roc_auc_ovr?.model,
      value: summary.best_roc_auc_ovr ? Number(summary.best_roc_auc_ovr.value).toFixed(4) : null,
    },
    {
      label: "Финальная инженерная схема",
      model: "Итоговый контур",
      value: summary.current_scheme || null,
    },
    {
      label: "SHAP reference",
      model: "Важность признаков",
      value: summary.feature_importance_reference || null,
    },
  ].filter((item) => item.value);

  target.innerHTML = rows.length
    ? `
      <div class="meta-table-wrap">
        <table class="meta-table meta-table-results">
          <thead>
            <tr>
              <th>Показатель</th>
              <th>Модель / слой</th>
              <th>Значение</th>
            </tr>
          </thead>
          <tbody>
            ${rows
              .map(
                (item, index) => `
                  <tr${index === 0 ? ' class="is-primary-result"' : ""}>
                    <th>${item.label}</th>
                    <td>${item.model}</td>
                    <td>${item.value}</td>
                  </tr>
                `
              )
              .join("")}
          </tbody>
        </table>
      </div>
    `
    : '<p class="chart-empty">Ключевые результаты пока не загружены.</p>';
}

function renderModelLeaderboard(metrics) {
  const target = document.getElementById("model-leaderboard");
  target.innerHTML = "";

  if (!metrics.length) {
    target.innerHTML = '<p class="chart-empty">Данные по лидерборду пока не загружены.</p>';
    return;
  }

  const rows = [...metrics]
    .filter((metric) => metric.model !== "Rule-based baseline" && !String(metric.model).startsWith("Hybrid Rules +"))
    .sort((a, b) => Number(b.macro_f1) - Number(a.macro_f1));
  const max = Math.max(...rows.map((item) => Number(item.macro_f1)), 1);
  const bestModel = rows[0]?.model;

  rows.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = `bar-row leaderboard-row${item.model === bestModel ? " is-best" : ""}`;
    row.innerHTML = `
      <div class="bar-meta">
        <strong>${index + 1}. ${item.model}</strong>
        <span>${Number(item.macro_f1).toFixed(4)}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(Number(item.macro_f1) / max) * 100}%; background:${leaderboardGradient(item.model, bestModel)};"></div>
      </div>
    `;
    target.appendChild(row);
  });

  const note = document.createElement("p");
  note.className = "chart-empty";
  note.textContent =
    "В лидерборде показаны только ML-модели. Гибридная схема оценивается отдельно как итоговый рабочий контур.";
  target.appendChild(note);
}

function renderModelMetrics(metrics) {
  const tbody = document.getElementById("model-metrics-table");
  tbody.innerHTML = "";

  if (!metrics.length) {
    tbody.innerHTML = '<tr><td colspan="7">Данные по моделям пока не загружены.</td></tr>';
    return;
  }

  const bestValues = {
    accuracy: Math.max(...metrics.map((metric) => Number(metric.accuracy))),
    macro_precision: Math.max(...metrics.map((metric) => Number(metric.macro_precision))),
    macro_recall: Math.max(...metrics.map((metric) => Number(metric.macro_recall))),
    macro_f1: Math.max(...metrics.map((metric) => Number(metric.macro_f1))),
    weighted_f1: Math.max(...metrics.map((metric) => Number(metric.weighted_f1))),
    roc_auc_ovr: Math.max(...metrics.map((metric) => Number(metric.roc_auc_ovr))),
  };
  const mlOnly = metrics.filter((metric) => metric.model !== "Rule-based baseline" && !String(metric.model).startsWith("Hybrid Rules +"));
  const bestMlMacroF1 = Math.max(...mlOnly.map((metric) => Number(metric.macro_f1)));
  const bestMacroF1Model = mlOnly.find((metric) => Number(metric.macro_f1) === bestMlMacroF1)?.model;

  metrics.forEach((metric) => {
    const row = document.createElement("tr");
    if (metric.model === bestMacroF1Model) {
      row.classList.add("is-best-model");
    }
    if (String(metric.model).startsWith("Hybrid Rules +")) {
      row.classList.add("is-hybrid-row");
    }
    row.innerHTML = `
      <td>${metric.model}${metric.model === bestMacroF1Model ? '<span class="table-winner">Лучшая ML-модель</span>' : ""}${String(metric.model).startsWith("Hybrid Rules +") ? '<span class="table-deployment">рабочий контур</span>' : ""}</td>
      <td class="${metricClass(Number(metric.accuracy), bestValues.accuracy)}">${Number(metric.accuracy).toFixed(4)}</td>
      <td class="${metricClass(Number(metric.macro_precision), bestValues.macro_precision)}">${Number(metric.macro_precision).toFixed(4)}</td>
      <td class="${metricClass(Number(metric.macro_recall), bestValues.macro_recall)}">${Number(metric.macro_recall).toFixed(4)}</td>
      <td class="${metricClass(Number(metric.macro_f1), bestValues.macro_f1)}">${Number(metric.macro_f1).toFixed(4)}</td>
      <td class="${metricClass(Number(metric.weighted_f1), bestValues.weighted_f1)}">${Number(metric.weighted_f1).toFixed(4)}</td>
      <td class="${metricClass(Number(metric.roc_auc_ovr), bestValues.roc_auc_ovr)}">${Number(metric.roc_auc_ovr).toFixed(4)}</td>
    `;
    tbody.appendChild(row);
  });
}

function renderConfusionMatrix(metrics, summary) {
  const target = document.getElementById("confusion-matrix");
  const bestModel = summary.best_macro_f1?.model;
  const model = metrics.find((item) => item.model === bestModel) || metrics[0];
  if (!model || !model.confusion_matrix) {
    target.innerHTML = '<p class="chart-empty">Матрица ошибок пока не загружена.</p>';
    return;
  }

  const labels = ["normal", "anomalous", "malicious"];
  const matrix = model.confusion_matrix;
  const max = Math.max(...matrix.flat(), 1);

  target.innerHTML = `
    <div class="matrix-title">
      <span>Лучшая модель по macro F1</span>
      <strong>${model.model}</strong>
    </div>
    <div class="meta-table-wrap">
      <table class="matrix-table">
        <thead>
          <tr>
            <th>True \\ Pred</th>
            ${labels.map((label) => `<th>${label}</th>`).join("")}
          </tr>
        </thead>
        <tbody>
          ${matrix
            .map(
              (row, rowIndex) => `
                <tr>
                  <th>${labels[rowIndex]}</th>
                  ${row
                    .map((value, columnIndex) => {
                      const intensity = value / max;
                      const diagonal = rowIndex === columnIndex ? " is-diagonal" : "";
                      return `<td class="matrix-td${diagonal}" style="background: rgba(23,103,109,${0.08 + intensity * 0.62})">${value}</td>`;
                    })
                    .join("")}
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </div>
    <p class="matrix-note">Строки показывают истинный класс, столбцы — предсказанный.</p>
  `;
}

function renderScenarioErrors(errorAnalysis, summary) {
  const target = document.getElementById("scenario-errors");
  const bestModel = summary.best_macro_f1?.model;
  const model = errorAnalysis.find((item) => item.model === bestModel) || errorAnalysis[0];
  target.innerHTML = "";

  if (!model) {
    target.innerHTML = '<p class="chart-empty">Анализ ошибок пока не загружен.</p>';
    return;
  }

  const counts = {};
  (model.sample_misclassifications || []).forEach((item) => {
    counts[item.scenario_type] = (counts[item.scenario_type] || 0) + 1;
  });
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(...entries.map(([, value]) => value), 1);

  if (!entries.length) {
    target.innerHTML = '<p class="chart-empty">Для выбранной модели нет загруженных примеров ошибок.</p>';
    return;
  }

  entries.forEach(([scenario, count]) => {
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-meta">
        <strong>${formatScenarioName(scenario)}</strong>
        <span>${count} прим.</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(count / max) * 100}%; background: linear-gradient(90deg, rgba(180,121,25,0.95), rgba(187,77,38,0.82));"></div>
      </div>
    `;
    target.appendChild(row);
  });

  const note = document.createElement("p");
  note.className = "chart-empty";
  note.textContent = `Показаны частоты по загруженным примерам ошибок классификации для ${model.model}.`;
  target.appendChild(note);
}

function renderOverfittingGap(rows, summary) {
  const target = document.getElementById("overfitting-gap");
  target.innerHTML = "";

  if (!rows.length) {
    target.innerHTML = '<p class="chart-empty">Данные по разрыву train/test пока не загружены.</p>';
    return;
  }

  const max = Math.max(...rows.map((row) => Number(row.macro_f1_gap)), 1);
  const bestModel = summary.best_macro_f1?.model;

  rows.forEach((row) => {
    const value = Number(row.macro_f1_gap);
    const card = document.createElement("div");
    card.className = "bar-row";
    card.innerHTML = `
      <div class="bar-meta">
        <strong>${row.model}</strong>
        <span>${value.toFixed(4)}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(value / max) * 100}%; background:${row.model === bestModel ? "linear-gradient(90deg, #17676d, rgba(47,117,84,0.92))" : "linear-gradient(90deg, rgba(187,77,38,0.82), rgba(214,164,59,0.9))"};"></div>
      </div>
    `;
    target.appendChild(card);
  });
}

function renderFeatureImportance(features) {
  const target = document.getElementById("feature-importance-chart");
  target.innerHTML = "";

  if (!features.length) {
    target.innerHTML = '<p class="chart-empty">Данные по важности признаков пока не загружены.</p>';
    return;
  }

  const max = Math.max(...features.map((item) => item.importance), 1);
  features.slice(0, 8).forEach((item) => {
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-meta">
        <strong>${formatFeatureName(item.feature)}</strong>
        <span>${Number(item.importance).toFixed(4)}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(item.importance / max) * 100}%; background: linear-gradient(90deg, #17676d, rgba(47,117,84,0.92));"></div>
      </div>
    `;
    target.appendChild(row);
  });
}

function renderPerformanceTable(rows) {
  const tbody = document.getElementById("performance-table");
  tbody.innerHTML = "";

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="3">Данные по производительности пока не загружены.</td></tr>';
    return;
  }

  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${row.configuration}</td>
      <td>${Number(row.average_event_ms).toFixed(6)}</td>
      <td>${Number(row.throughput_eps).toFixed(2)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderDemo(demo) {
  const policy = demo.policy || {};
  populateSelect("demo-client", policy.allowed_clients || []);
  populateSelect("demo-transport", policy.allowed_transports || []);

  const examples = document.getElementById("demo-examples");
  examples.innerHTML = "";
  (demo.sample_prompts || []).forEach((prompt) => {
    const scenario = typeof prompt === "string"
      ? { title: "Сценарий", expected_decision: guessExpectedDecision(prompt), prompt }
      : prompt;
    const button = document.createElement("button");
    button.type = "button";
    button.className = `demo-example tone-${scenario.expected_decision}`;
    button.innerHTML = `
      <div class="demo-example-title">
        <strong>${scenario.title}</strong>
        <span class="demo-example-label label-${scenario.expected_decision}">${scenario.expected_decision}</span>
      </div>
      <div class="demo-example-prompt">${scenario.prompt}</div>
    `;
    button.addEventListener("click", () => {
      document.getElementById("demo-prompt").value = scenario.prompt;
      runDemo();
    });
    examples.appendChild(button);
  });

  document.getElementById("demo-run").addEventListener("click", runDemo);
  document.getElementById("demo-reset").addEventListener("click", () => {
    state.demoSession = createDemoSession();
    runDemo();
  });

  runDemo();
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
  renderDemoResult(result, demo.current_scheme || state.raw.evaluation?.summary?.current_scheme || "Rules + ML");
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

  const payloadSize = estimatePayloadSize(prompt, params);
  return {
    prompt,
    client_id: clientId,
    transport_type: transportType,
    jsonrpc_method: "tools/call",
    tool_name: toolName,
    server_id: serverId,
    params,
    payload_size: payloadSize,
  };
}

function evaluateDemoEvent(event, policy, session) {
  const requestFeatures = buildRequestFeatures(event, session, policy);
  const accessMatches = evaluateAccessControl(event, policy);
  const requestRuleMatches = evaluateRules(event, policy, session, {
    response_size: 0,
    response_time_ms: 0,
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
    matches.push({
      name: "disallowed_transport",
      severity: "block",
      reason: `Транспорт ${event.transport_type} не разрешен политикой.`,
    });
  }

  const allowedTools = allowlist[event.client_id];
  if (!allowedTools) {
    matches.push({
      name: "unknown_client",
      severity: "block",
      reason: `Клиент ${event.client_id} не зарегистрирован в политике доступа.`,
    });
  } else if (!allowedTools.includes(event.tool_name)) {
    matches.push({
      name: "tool_not_allowed_for_client",
      severity: "block",
      reason: `Инструмент ${event.tool_name} не разрешен для клиента ${event.client_id}.`,
    });
  }

  const expectedServer = toolServerMap[event.tool_name];
  if (expectedServer && event.server_id !== expectedServer) {
    matches.push({
      name: "tool_server_mismatch",
      severity: "block",
      reason: `Инструмент ${event.tool_name} должен обращаться к ${expectedServer}, а не к ${event.server_id}.`,
    });
  }

  return matches;
}

function evaluateRules(event, policy, session, responseAware) {
  const matches = [];
  const values = flattenParamValues(event.params);
  const lowerValues = values.map((value) => value.toLowerCase());

  if (event.payload_size > policy.max_payload_size) {
    matches.push({
      name: "oversized_payload",
      severity: "warn",
      reason: "Размер payload превышает настроенный порог.",
    });
  }

  if ((responseAware.response_size || 0) > policy.max_response_size) {
    matches.push({
      name: "oversized_response",
      severity: "warn",
      reason: "Размер ответа превышает настроенный порог.",
    });
  }

  if (session.totalCalls >= policy.high_frequency_threshold) {
    matches.push({
      name: "high_frequency_calls",
      severity: "warn",
      reason: "Частота вызовов в demo-сессии превышает ожидаемый порог.",
    });
  }

  const sensitiveFragment = lowerValues.find((value) => (policy.blocked_paths || []).some((blocked) => value.includes(blocked)));
  if (sensitiveFragment) {
    matches.push({
      name: "sensitive_path_access",
      severity: "block",
      reason: `Обнаружен чувствительный путь: ${sensitiveFragment}.`,
    });
  }

  const url = values.find((value) => value.startsWith("http://") || value.startsWith("https://"));
  if (url) {
    const host = extractHost(url);
    if ((policy.blocked_hosts || []).includes(host) || isPrivateHost(host)) {
      matches.push({
        name: "private_address_access",
        severity: "block",
        reason: `Обнаружено обращение к приватному или служебному хосту: ${host}.`,
      });
    }
  }

  if (event.tool_name === "filesystem.read_file") {
    const path = String(event.params.path || "");
    if (path && !(policy.safe_file_roots || []).some((root) => path.startsWith(root))) {
      matches.push({
        name: "path_outside_safe_roots",
        severity: "warn",
        reason: "Операция чтения направлена на путь вне safe roots.",
      });
    }
  }

  const path = String(event.params.path || "");
  if (path.startsWith("/private") && event.tool_name.includes("read")) {
    matches.push({
      name: "private_backend_path_access",
      severity: "block",
      reason: "Попытка доступа к приватному backend-path через MCP.",
    });
  }

  return deduplicateMatches(matches);
}

function deduplicateMatches(matches) {
  const seen = new Set();
  return matches.filter((match) => {
    if (seen.has(match.name)) {
      return false;
    }
    seen.add(match.name);
    return true;
  });
}

function synthesizeBackendResponse(event) {
  if (event.tool_name === "filesystem.read_file") {
    const path = String(event.params.path || "");
    const preview = `Содержимое ${path} успешно прочитано в пределах лабораторного backend API.`;
    return {
      response_size: path.includes("README") ? 2400 : 3600,
      response_time_ms: path.includes("README") ? 90 : 420,
      is_error: false,
      error_code: "",
      preview,
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
  if (ruleMatches.some((match) => match.severity === "block")) {
    return "block";
  }
  if (riskScore >= policy.block_risk_threshold) {
    return "block";
  }
  if (ruleMatches.some((match) => match.severity === "warn") || riskScore >= policy.warn_risk_threshold) {
    return "warn";
  }
  return "allow";
}

function buildRationale(decision, riskScore, ruleMatches, policy) {
  const blockMatches = ruleMatches.filter((match) => match.severity === "block");
  const warnMatches = ruleMatches.filter((match) => match.severity === "warn");

  if (blockMatches.length) {
    return blockMatches.map((match) => match.reason).join("; ");
  }
  if (decision === "block" && riskScore >= policy.block_risk_threshold) {
    return "ML-оценка риска превысила block threshold.";
  }
  if (warnMatches.length) {
    return warnMatches.map((match) => match.reason).join("; ");
  }
  if (decision === "warn") {
    return "ML-оценка риска превысила warn threshold.";
  }
  return "Блокирующие правила не сработали, итоговый риск остался в безопасной зоне.";
}

function buildTrace(event, requestFeatures, fullFeatures, ruleMatches, backendResponse, mlClass, riskScore, decision, rationale) {
  const trace = [
    {
      step: 1,
      title: "Интерпретация запроса",
      items: [
        `tool call: ${event.tool_name}`,
        `server: ${event.server_id}`,
        `params: ${JSON.stringify(event.params)}`,
      ],
    },
    {
      step: 2,
      title: "Request-level признаки",
      items: [
        `payload_size=${requestFeatures.payload_size}`,
        `arg_count=${requestFeatures.arg_count}`,
        `sensitive_path=${requestFeatures.sensitive_path_flag}`,
        `private_ip=${requestFeatures.private_ip_flag}`,
        `sensitive_keyword=${requestFeatures.sensitive_keyword_flag}`,
      ],
    },
    {
      step: 3,
      title: "Policy и rule checks",
      items: ruleMatches.length
        ? ruleMatches.map((match) => `${match.severity.toUpperCase()}: ${formatRuleName(match.name)}`)
        : ["Явные policy- или rule-срабатывания отсутствуют."],
    },
  ];

  if (backendResponse) {
    trace.push({
      step: 4,
      title: "Response-aware этап",
      items: [
        `response_size=${fullFeatures.response_size}`,
        `response_time_ms=${fullFeatures.response_time_ms}`,
        `preview: ${backendResponse.preview}`,
      ],
    });
  } else {
    trace.push({
      step: 4,
      title: "Response-aware этап",
      items: ["Ветка ранней блокировки: backend-response отсутствует."],
    });
  }

  trace.push({
    step: 5,
      title: "ML и итоговое решение",
      tone: decision,
      items: [
        `класс ML-компонента: ${mlClass}`,
        `risk_score=${riskScore.toFixed(2)}`,
        `решение=${decision}`,
        rationale,
    ],
  });

  return trace;
}

function updateDemoSession(event, result, session) {
  session.totalCalls += 1;
  if (result.backendResponse?.is_error) {
    session.failedCalls += 1;
  }
  if (event.tool_name) {
    session.lastToolName = event.tool_name;
  }
  if (result.features.sensitive_path_flag || result.features.private_ip_flag) {
    session.sensitiveHits += 1;
  }
}

function renderDemoResult(result, currentScheme) {
  const summary = document.getElementById("demo-summary");
  summary.innerHTML = `
    <div class="summary-grid">
      <div class="summary-card">
        <span>Tool call</span>
        <strong>${result.event.tool_name}</strong>
      </div>
      <div class="summary-card">
        <span>ML-компонент</span>
        <strong>${result.mlClass} / ${currentScheme}</strong>
      </div>
      <div class="summary-card">
        <span>Итоговое решение</span>
        <strong class="badge decision-${result.decision}">${result.decision}</strong>
      </div>
    </div>
  `;

  const trace = document.getElementById("demo-trace");
  trace.innerHTML = result.trace
    .map(
      (step) => `
        <div class="timeline-step${step.tone ? ` tone-${step.tone}` : ""}">
          <div class="timeline-marker">
            <span class="timeline-step-number">${step.step}</span>
          </div>
          <div class="trace-card">
            <span>${step.title}</span>
            ${step.tone ? `<strong class="timeline-decision">${formatCategoryName(step.tone, "decision")}</strong>` : ""}
          <ul>${step.items.map((item) => `<li>${item}</li>`).join("")}</ul>
          </div>
        </div>
      `
    )
    .join("");

  const response = document.getElementById("demo-response");
  response.innerHTML = `
    <div class="response-card">
      <span>Итоговая интерпретация</span>
      <strong>${formatCategoryName(result.mlClass, "label")} / ${formatCategoryName(result.decision, "decision")}</strong>
      <div class="response-preview">${result.rationale}</div>
      ${
        result.backendResponse
          ? `<div class="response-preview">Ответ backend: ${result.backendResponse.preview}</div>`
          : `<div class="response-preview">Вызов был остановлен до обращения к MCP / backend.</div>`
      }
    </div>
  `;
}

function renderFilters(events) {
  const container = document.getElementById("filters");
  const labels = uniqueValues(events.map((event) => event.label));
  const decisions = uniqueValues(events.map((event) => event.decision));
  const tools = uniqueValues(events.map((event) => event.tool_name));
  container.innerHTML = "";

  container.appendChild(buildSelect("Класс", "label", labels, "label"));
  container.appendChild(buildSelect("Решение", "decision", decisions, "decision"));
  container.appendChild(buildSelect("Инструмент", "tool", tools, "tool"));

  container.querySelectorAll("select").forEach((select) => {
    select.addEventListener("change", (event) => {
      state.filters[event.target.name] = event.target.value;
      applyFilters();
    });
  });
}

function buildSelect(labelText, name, values, type) {
  const label = document.createElement("label");
  const options = [`<option value="all">Все</option>`]
    .concat(values.map((value) => `<option value="${value}">${formatCategoryName(value, type)}</option>`))
    .join("");
  label.innerHTML = `
    <span>${labelText}</span>
    <select name="${name}">
      ${options}
    </select>
  `;
  return label;
}

function applyFilters() {
  const events = state.raw.events.filter((event) => {
    return (
      (state.filters.label === "all" || event.label === state.filters.label) &&
      (state.filters.decision === "all" || event.decision === state.filters.decision) &&
      (state.filters.tool === "all" || event.tool_name === state.filters.tool)
    );
  });
  state.filteredEvents = events;
  renderScatter(events);
  renderLegend();
  renderEventsTable(events);
  if (events[0]) {
    renderEventDetail(events[0]);
    highlightFirstRow();
  } else {
    document.getElementById("event-detail").innerHTML =
      '<p class="detail-empty">По текущим фильтрам события не найдены.</p>';
  }
}

function renderScatter(events) {
  const svg = document.getElementById("scatter-plot");
  const width = 760;
  const height = 420;
  const margin = { top: 24, right: 20, bottom: 46, left: 58 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;
  const maxPayload = Math.max(...events.map((event) => event.payload_size), 1);
  const maxLatency = Math.max(...events.map((event) => event.response_time_ms), 1);

  const axisLines = `
    <line x1="${margin.left}" y1="${height - margin.bottom}" x2="${width - margin.right}" y2="${height - margin.bottom}" stroke="rgba(32,22,15,0.25)" />
    <line x1="${margin.left}" y1="${margin.top}" x2="${margin.left}" y2="${height - margin.bottom}" stroke="rgba(32,22,15,0.25)" />
  `;

  const gridLines = Array.from({ length: 4 }, (_, index) => {
    const ratio = (index + 1) / 4;
    const y = margin.top + innerHeight - innerHeight * ratio;
    return `<line x1="${margin.left}" y1="${y}" x2="${width - margin.right}" y2="${y}" stroke="rgba(32,22,15,0.08)" />`;
  }).join("");

  const points = events
    .map((event) => {
      const x = margin.left + (event.payload_size / maxPayload) * innerWidth;
      const y = margin.top + innerHeight - (event.response_time_ms / maxLatency) * innerHeight;
      const color = pickColor(event.label, "label");
      const radius = 5 + event.risk_score * 8;
      return `
        <circle
          cx="${x.toFixed(2)}"
          cy="${y.toFixed(2)}"
          r="${radius.toFixed(2)}"
          fill="${color}"
          fill-opacity="0.7"
          stroke="rgba(255,255,255,0.85)"
          stroke-width="1.2"
        >
          <title>${event.tool_name} | ${event.label} | risk ${event.risk_score}</title>
        </circle>
      `;
    })
    .join("");

  svg.innerHTML = `
    <rect x="0" y="0" width="${width}" height="${height}" fill="transparent"></rect>
    ${gridLines}
    ${axisLines}
    ${points}
    <text x="${width / 2}" y="${height - 10}" text-anchor="middle" fill="#66584c" font-size="13">Размер запроса (payload_size)</text>
    <text x="18" y="${height / 2}" text-anchor="middle" fill="#66584c" font-size="13" transform="rotate(-90 18 ${height / 2})">Время ответа, мс</text>
  `;
}

function renderLegend() {
  const legend = document.getElementById("scatter-legend");
  legend.innerHTML = ["normal", "malicious", "anomalous"]
    .map((label) => {
      return `
        <div class="legend-item">
          <span class="legend-dot" style="background:${pickColor(label, "label")}"></span>
          <span>${formatCategoryName(label, "label")}</span>
        </div>
      `;
    })
    .join("");
}

function renderEventsTable(events) {
  const tbody = document.getElementById("events-table");
  tbody.innerHTML = "";
  const visibleEvents = selectRepresentativeEvents(events, 40);
  visibleEvents.forEach((event, index) => {
    const row = document.createElement("tr");
    row.dataset.eventId = String(event.id);
    row.innerHTML = `
      <td>${event.id}</td>
      <td><span class="badge label-${event.label}">${formatCategoryName(event.label, "label")}</span></td>
      <td><span class="badge decision-${event.decision}">${formatCategoryName(event.decision, "decision")}</span></td>
      <td>${event.tool_name}</td>
      <td>${event.payload_size}</td>
      <td>${event.response_time_ms}</td>
      <td>${event.risk_score.toFixed(2)}</td>
    `;
    row.addEventListener("click", () => {
      renderEventDetail(event);
      document.querySelectorAll("#events-table tr").forEach((item) => item.classList.remove("is-active"));
      row.classList.add("is-active");
    });
    if (index === 0) {
      row.classList.add("is-active");
    }
    tbody.appendChild(row);
  });
}

function renderEventDetail(event) {
  const target = document.getElementById("event-detail");
  const tags = []
    .concat(event.rule_names.map((name) => `<span class="detail-tag">${formatRuleName(name)}</span>`))
    .concat(event.sensitive_path_flag ? ['<span class="detail-tag">чувствительный путь</span>'] : [])
    .concat(event.private_ip_flag ? ['<span class="detail-tag">приватный хост</span>'] : [])
    .concat(event.sensitive_keyword_flag ? ['<span class="detail-tag">чувствительные ключевые слова</span>'] : []);

  target.innerHTML = `
    <div class="detail-meta">
      <div>
        <p class="eyebrow">Событие ${event.id}</p>
        <h3>${event.tool_name}</h3>
      </div>
      <div class="detail-line">
        <span>Классификация</span>
        <div class="detail-tags">
          <span class="badge label-${event.label}">${formatCategoryName(event.label, "label")}</span>
          <span class="badge decision-${event.decision}">${formatCategoryName(event.decision, "decision")}</span>
        </div>
      </div>
      <div class="detail-line">
        <span>Клиент / сервер</span>
        <strong>${event.client_id} -> ${event.server_id}</strong>
      </div>
      <div class="detail-line">
        <span>Сценарий</span>
        <strong>${formatScenarioName(event.scenario_type)}</strong>
      </div>
      <div class="detail-line">
        <span>Транспорт</span>
        <strong>${event.transport_type}</strong>
      </div>
      <div class="detail-line">
        <span>Размер запроса / ответа</span>
        <strong>${event.payload_size} bytes / ${event.response_size} bytes</strong>
      </div>
      <div class="detail-line">
        <span>Время ответа</span>
        <strong>${event.response_time_ms} ms</strong>
      </div>
      <div class="detail-line">
        <span>Оценка риска</span>
        <strong>${event.risk_score.toFixed(2)}</strong>
      </div>
      <div class="detail-line">
        <span>Обоснование</span>
        <p>${formatRationale(event.rationale)}</p>
      </div>
      <div class="detail-line">
        <span>Сигналы</span>
        <div class="detail-tags">${tags.join("") || '<span class="detail-tag">явные флаги отсутствуют</span>'}</div>
      </div>
    </div>
  `;
}

function highlightFirstRow() {
  const firstRow = document.querySelector("#events-table tr");
  if (firstRow) {
    firstRow.classList.add("is-active");
  }
}

function selectRepresentativeEvents(events, limit) {
  if (events.length <= limit) {
    return events;
  }

  const labelOrder = ["normal", "malicious", "anomalous"];
  const buckets = new Map(labelOrder.map((label) => [label, []]));

  events.forEach((event) => {
    if (buckets.has(event.label)) {
      buckets.get(event.label).push(event);
    }
  });

  const selected = [];
  const seen = new Set();
  const perLabel = Math.max(1, Math.floor(limit / labelOrder.length));

  labelOrder.forEach((label) => {
    const bucket = buckets.get(label) || [];
    bucket.slice(0, perLabel).forEach((event) => {
      if (!seen.has(event.id)) {
        selected.push(event);
        seen.add(event.id);
      }
    });
  });

  for (const event of events) {
    if (selected.length >= limit) {
      break;
    }
    if (!seen.has(event.id)) {
      selected.push(event);
      seen.add(event.id);
    }
  }

  return selected;
}

function estimatePayloadSize(prompt, params) {
  return Math.max(
    220,
    prompt.length * 18 +
      Object.values(params).reduce((sum, value) => sum + String(value).length * 6, 0)
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
  return prompt
    .replace(/^найди/i, "")
    .replace(/^выполни поиск/i, "")
    .trim() || prompt;
}

function renderDistributionCard(title, value) {
  const parsed = parseDistribution(value);
  return `
    <div class="meta-card distribution-card">
      <span>${title}</span>
      <div class="distribution-tags">
        ${parsed
          .map(
            (item) => `
              <div class="distribution-tag">
                <small>${item.label}</small>
                <strong>${item.value}</strong>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function parseDistribution(value) {
  if (!value) {
    return [];
  }
  const cleaned = String(value)
    .replace(/[{}']/g, "")
    .split(",")
    .map((chunk) => chunk.trim())
    .filter(Boolean);
  return cleaned.map((chunk) => {
    const [label, raw] = chunk.split(":").map((part) => part.trim());
    return { label, value: raw };
  });
}

function leaderboardGradient(model, bestModel) {
  if (model === bestModel) {
    return "linear-gradient(90deg, #17676d, rgba(47,117,84,0.95))";
  }
  return "linear-gradient(90deg, rgba(187,77,38,0.78), rgba(214,164,59,0.9))";
}

function metricClass(value, bestValue) {
  return Math.abs(value - bestValue) < 1e-9 ? "metric-best" : "";
}

function guessExpectedDecision(prompt) {
  const lower = prompt.toLowerCase();
  if (lower.includes("/private") || lower.includes("169.254.169.254")) {
    return "block";
  }
  if (lower.includes("token") || lower.includes("secret") || lower.includes("password")) {
    return "warn";
  }
  return "allow";
}

function flattenParamValues(value) {
  if (Array.isArray(value)) {
    return value.flatMap(flattenParamValues);
  }
  if (value && typeof value === "object") {
    return Object.values(value).flatMap(flattenParamValues);
  }
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
  } catch (error) {
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

function uniqueValues(values) {
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

function pickColor(value, type) {
  if (type === "label" || type === "decision") {
    return COLORS[value] || "#66584c";
  }
  return "#17676d";
}

function formatCategoryName(value, type) {
  if (!value) {
    return value;
  }

  if (type === "label") {
    return {
      normal: "normal",
      anomalous: "anomalous",
      malicious: "malicious",
    }[value] || value;
  }

  if (type === "decision") {
    return {
      allow: "allow",
      warn: "warn",
      block: "block",
    }[value] || value;
  }

  return value;
}

function formatScenarioName(value) {
  const aliases = {
    benign_usage: "обычное корректное использование",
    benign_large_transfer: "крупный, но легитимный обмен данными",
    benign_error_recovery: "штатное восстановление после ошибки",
    sensitive_file_access: "доступ к чувствительному файлу",
    private_host_access: "обращение к приватному хосту",
    covert_safe_root_access: "пограничный доступ в зоне safe roots",
    public_endpoint_exfiltration: "массовый вывод через публичный endpoint",
    oversized_sensitive_query: "крупный чувствительный запрос",
    high_latency_search: "медленный поисковый сценарий",
    error_burst_like: "серия сбоев, похожая на аномалию",
    noisy_borderline_search: "шумный пограничный поиск",
  };
  return aliases[value] || value;
}

function formatRuleName(value) {
  const aliases = {
    disallowed_transport: "disallowed_transport",
    unknown_client: "unknown_client",
    tool_not_allowed_for_client: "tool_not_allowed_for_client",
    tool_server_mismatch: "tool_server_mismatch",
    sensitive_path_access: "sensitive_path_access",
    private_address_access: "private_address_access",
    path_outside_safe_roots: "path_outside_safe_roots",
    private_backend_path_access: "private_backend_path_access",
    sensitive_export_scope: "sensitive_export_scope",
    oversized_payload: "oversized_payload",
    oversized_response: "oversized_response",
    high_frequency_calls: "high_frequency_calls",
    blocked_tool: "blocked_tool",
  };
  return aliases[value] || value;
}

function formatFeatureName(feature) {
  const aliases = {
    feature_response_size: "response_size",
    feature_response_time_ms: "response_time_ms",
    feature_payload_size: "payload_size",
    feature_transport_type_streamable_http: "transport=streamable_http",
    feature_transport_type_stdio: "transport=stdio",
    "feature_tool_name_filesystem.search": "tool=filesystem.search",
    "feature_tool_name_web.fetch": "tool=web.fetch",
    feature_sensitive_keyword_flag_True: "sensitive_keyword=True",
    feature_arg_count: "arg_count",
    feature_tools_called_last_session: "tools_called_last_session",
    feature_failed_calls_last_session: "failed_calls_last_session",
    feature_private_ip_flag_True: "private_ip=True",
    feature_sensitive_path_flag_True: "sensitive_path=True",
    feature_external_url_flag_True: "external_url=True",
  };
  return aliases[feature] || feature.replace(/^feature_/, "");
}

function formatRationale(value) {
  const direct = {
    "No blocking rules matched and risk score is within safe range.":
      "Блокирующие правила не сработали, итоговый риск находится в допустимой зоне.",
    "ML risk score exceeded warn threshold.":
      "ML-оценка риска превысила порог предупреждения.",
    "ML risk score exceeded block threshold.":
      "ML-оценка риска превысила порог блокировки.",
    "Read operation targets a path outside allowed roots.":
      "Операция чтения направлена на путь вне разрешенных корней.",
    "Attempted access to a private backend path exposed through MCP.":
      "Попытка доступа к приватному backend-пути, опубликованному через MCP.",
    "Export request targets full scope and may expose sensitive records.":
      "Запрос на экспорт полного scope может привести к раскрытию чувствительных данных.",
    "Payload size exceeds the configured threshold.":
      "Размер payload превышает настроенный порог.",
    "Response size exceeds the configured threshold.":
      "Размер ответа превышает настроенный порог.",
    "Session frequency is above the expected threshold.":
      "Частота вызовов в сессии превышает ожидаемый порог.",
  };
  if (direct[value]) {
    return direct[value];
  }
  if (typeof value === "string" && value.startsWith("Attempted access to sensitive path fragment: ")) {
    const suffix = value.replace("Attempted access to sensitive path fragment: ", "");
    return `Попытка доступа к чувствительному пути: ${suffix}.`;
  }
  if (typeof value === "string" && value.startsWith("Attempted access to blocked or private host: ")) {
    const suffix = value.replace("Attempted access to blocked or private host: ", "");
    return `Попытка обращения к закрытому или приватному хосту: ${suffix}.`;
  }
  return value;
}

document.addEventListener("DOMContentLoaded", init);
