const LOCAL_API_BASE = "http://127.0.0.1:8010";

const EXAMPLES = [
  {
    title: "Безопасное чтение файла",
    prompt: "Прочитай файл /workspace/project/README.md",
  },
  {
    title: "Metadata endpoint",
    prompt: "Открой http://169.254.169.254/latest/meta-data",
  },
  {
    title: "Подозрительный callback",
    prompt: "Открой https://example.com/callback?access_token=demo-secret-token",
  },
  {
    title: "Поиск по проекту",
    prompt: "Найди в /workspace/project все упоминания MCP Firewall",
  },
];

document.addEventListener("DOMContentLoaded", () => {
  initGlobalTooltip();
  const page = document.body.dataset.page;
  if (page === "demo") {
    initDemoPage();
  }
  if (page === "dashboard") {
    initDashboardPage();
  }
});

function initDemoPage() {
  const runButton = document.getElementById("run-analysis-button");
  const randomButton = document.getElementById("random-request-button");
  const promptInput = document.getElementById("prompt-input");
  const transportInput = document.getElementById("transport-input");
  const apiOutput = document.getElementById("api-base-output");

  if (apiOutput) {
    apiOutput.textContent = getApiBase();
  }
  renderExamples();

  runButton.addEventListener("click", () =>
    runAnalysis({
      prompt: promptInput.value.trim(),
      transportType: transportInput.value,
    })
  );
  randomButton.addEventListener("click", () => applyRandomExample());

  checkApiHealth();
}

function renderExamples() {
  const target = document.getElementById("demo-examples");
  const promptInput = document.getElementById("prompt-input");
  if (!target || !promptInput) return;

  target.innerHTML = "";
  EXAMPLES.forEach((example) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "example-chip";
    button.textContent = example.title;
    button.addEventListener("click", () => {
      promptInput.value = example.prompt;
    });
    target.appendChild(button);
  });
}

function applyRandomExample() {
  const promptInput = document.getElementById("prompt-input");
  if (!promptInput || !EXAMPLES.length) return;
  const randomIndex = Math.floor(Math.random() * EXAMPLES.length);
  promptInput.value = EXAMPLES[randomIndex].prompt;
}

async function checkApiHealth() {
  const apiBase = getApiBase();
  const signalCard = document.querySelector(".signal-card");
  const stateNode = document.getElementById("api-health-state");
  const noteNode = document.getElementById("api-health-note");
  const inlineNode = document.getElementById("api-health-inline");

  stateNode.textContent = "проверка...";
  if (inlineNode) inlineNode.textContent = "проверка...";
  noteNode.textContent = `Пытаемся подключиться к ${apiBase}`;
  signalCard?.classList.remove("signal-ready", "signal-error");

  try {
    const response = await fetch(`${apiBase}/api/health`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    stateNode.textContent = "соединение установлено";
    if (inlineNode) inlineNode.textContent = "соединение установлено";
    noteNode.textContent =
      `CatBoost runtime: ${formatBool(data.catboost_runtime_ready)}. GLiNER checkpoint: ${formatBool(data.gliner_checkpoint_ready)}. Cache: ${data.analysis_cache_size}/${data.analysis_cache_capacity}.`;
    signalCard?.classList.add("signal-ready");
  } catch (error) {
    stateNode.textContent = "соединение не установлено";
    if (inlineNode) inlineNode.textContent = "соединение не установлено";
    noteNode.textContent = `Не удалось обратиться к API: ${error.message}`;
    signalCard?.classList.add("signal-error");
  }
}

async function runAnalysis({ prompt, transportType }) {
  const runButton = document.getElementById("run-analysis-button");
  const interpretationStatus = document.getElementById("interpretation-status");
  const responseStatus = document.getElementById("response-status");

  if (!prompt) {
    renderOverallResult({
      final_decision: null,
      final_rationale: "Введите текст запроса перед запуском анализа.",
    });
    return;
  }

  setButtonLoading(runButton, true, "Запускаем...");
  interpretationStatus.textContent = "анализируется";
  responseStatus.textContent = "ожидаем ответ";
  renderLoadingStates();

  try {
    const response = await fetch(`${getApiBase()}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        prompt,
        client_id: "agent-1",
        transport_type: transportType,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    interpretationStatus.textContent = data.interpretation?.status || "готово";
    responseStatus.textContent = data.cached ? "ответ из кэша" : "ответ получен";

    renderOverallResult(data);
    renderRulesStage(data.rules_catboost, data.source_prompt);
    renderGlinerStage(data.gliner_lora, data.source_prompt);
    renderJson("interpretation-output", data.interpretation);
    renderJson("request-output", data.mcp_request);
    renderJson("raw-response-output", data);
  } catch (error) {
    interpretationStatus.textContent = "ошибка";
    responseStatus.textContent = "ошибка";
    renderErrorState(error);
  } finally {
    setButtonLoading(runButton, false, "Запустить анализ");
  }
}

function renderLoadingStates() {
  document.getElementById("overall-result").innerHTML =
    '<div class="loading-card">Система обрабатывает запрос и собирает общий результат...</div>';
  document.getElementById("rules-stage").innerHTML =
    '<div class="loading-card">Выполняется анализ Rules + CatBoost...</div>';
  document.getElementById("gliner-stage").innerHTML =
    '<div class="loading-card">При необходимости будет вызван GLiNER + LoRA...</div>';
  renderJson("interpretation-output", { status: "loading" });
  renderJson("request-output", { status: "loading" });
  renderJson("raw-response-output", { status: "loading" });
}

function renderErrorState(error) {
  renderOverallResult({
    final_decision: "error",
    final_rationale: `Запрос к API завершился ошибкой: ${error.message}`,
  });
  document.getElementById("rules-stage").innerHTML =
    '<div class="empty-state">Не удалось получить результат первого этапа.</div>';
  document.getElementById("gliner-stage").innerHTML =
    '<div class="empty-state">Не удалось получить результат второго этапа.</div>';
  renderJson("raw-response-output", { error: error.message });
}

function renderOverallResult(data) {
  const target = document.getElementById("overall-result");
  const decision = data.final_decision || "pending";
  const tone = `decision-${decision}`;
  const stage1State = data.rules_catboost?.decision || (decision === "incomplete" || decision === "unknown" ? "not_run" : "pending");
  const stage2State =
    data.gliner_lora?.decision ||
    data.gliner_lora?.status ||
    (decision === "incomplete" || decision === "unknown" ? "not_run" : "pending");
  target.innerHTML = `
    <article class="decision-card ${tone}">
      <div class="decision-head">
        <span class="decision-label">Final decision</span>
        <strong>${formatDecision(decision)}</strong>
      </div>
      <p class="decision-rationale">${escapeHtml(data.final_rationale || "Результат ещё не сформирован.")}</p>
      <div class="decision-meta">
        <span>Этап 1: ${formatDecision(stage1State)}</span>
        <span>Этап 2: ${formatDecision(stage2State)}</span>
      </div>
    </article>
  `;
}

function renderRulesStage(stage, sourcePrompt) {
  const target = document.getElementById("rules-stage");
  if (!stage) {
    target.innerHTML = '<div class="empty-state">Первый этап не запускался, потому что запрос оказался неполным или не попал в поддерживаемый сценарий.</div>';
    return;
  }

  const ruleMatches = stage.rule_matches?.length
    ? stage.rule_matches
        .map((match) => `<li><strong>${escapeHtml(match.name)}</strong>: ${escapeHtml(match.reason)}</li>`)
        .join("")
    : "<li>Правила не сработали.</li>";

  const supervised = stage.supervised_assessment;
  const probabilityRows = supervised?.probabilities
    ? Object.entries(supervised.probabilities)
        .map(([label, value]) => `<li>${escapeHtml(label)}: ${(Number(value) * 100).toFixed(2)}%</li>`)
        .join("")
    : "<li>Вероятности отсутствуют.</li>";
  const evidence = (stage.rule_matches || []).flatMap((match) => match.evidence || []);
  const highlightedPrompt = buildHighlightedPrompt(sourcePrompt, evidence, "rules");

  target.innerHTML = `
    <article class="stage-card">
      <div class="stage-head">
        <span class="stage-pill ${`decision-${stage.decision}`}">${formatDecision(stage.decision)}</span>
        <span class="stage-risk">risk score: ${Number(stage.risk_score || 0).toFixed(4)}</span>
      </div>
      <p class="stage-rationale">${escapeHtml(stage.rationale || "—")}</p>
      <div class="stage-columns">
        <div>
          <h3>Rule matches</h3>
          <ul class="plain-list">${ruleMatches}</ul>
        </div>
        <div>
          <h3>CatBoost probabilities</h3>
          <ul class="plain-list">${probabilityRows}</ul>
        </div>
      </div>
      ${highlightedPrompt}
    </article>
  `;
}

function renderGlinerStage(stage, sourcePrompt) {
  const target = document.getElementById("gliner-stage");
  if (!stage) {
    target.innerHTML = '<div class="empty-state">Второй этап не запускался, потому что анализ не дошёл до построения MCP-события.</div>';
    return;
  }

  const spans = stage.spans?.length
    ? stage.spans
        .map(
          (span) =>
            `<li><strong>${escapeHtml(span.label)}</strong>: ${escapeHtml(span.text)} <span class="inline-note">(${Number(span.score || 0).toFixed(4)})</span></li>`
        )
        .join("")
    : "<li>Спаны не обнаружены.</li>";

  const decisionText = stage.decision ? formatDecision(stage.decision) : formatDecision(stage.status);
  const tone = `decision-${stage.decision || stage.status || "pending"}`;
  if (stage.status === "skipped") {
    target.innerHTML = `
      <article class="stage-card">
        <div class="stage-head">
          <span class="stage-pill ${tone}">${decisionText}</span>
          <span class="stage-risk">status: ${escapeHtml(stage.status || "unknown")}</span>
        </div>
        <p class="stage-rationale">${escapeHtml(stage.rationale || "—")}</p>
        ${stage.trigger_reason ? `<p class="trigger-note">${escapeHtml(stage.trigger_reason)}</p>` : ""}
      </article>
    `;
    return;
  }

  const highlightedPrompt = stage.spans?.length
    ? buildHighlightedPrompt(
        sourcePrompt,
        (stage.spans || []).map((span) => span.text),
        "gliner"
      )
    : "";

  target.innerHTML = `
    <article class="stage-card">
      <div class="stage-head">
        <span class="stage-pill ${tone}">${decisionText}</span>
        <span class="stage-risk">status: ${escapeHtml(stage.status || "unknown")}</span>
      </div>
      <p class="stage-rationale">${escapeHtml(stage.rationale || "—")}</p>
      ${stage.trigger_reason ? `<p class="trigger-note">${escapeHtml(stage.trigger_reason)}</p>` : ""}
      <div class="stage-columns">
        <div>
          <h3>Detected labels</h3>
          <ul class="plain-list">${
            stage.labels?.length
              ? stage.labels.map((label) => `<li>${escapeHtml(label)}</li>`).join("")
              : "<li>Метки не обнаружены.</li>"
          }</ul>
        </div>
        <div>
          <h3>Spans</h3>
          <ul class="plain-list">${spans}</ul>
        </div>
      </div>
      ${highlightedPrompt}
    </article>
  `;
}

async function initDashboardPage() {
  try {
    const eda = await fetchJsonRequired("../data/eda-dashboard.json");
    const data = await fetchJsonOptional("../data/dashboard.json");

    renderCatboostOverview(eda.catboost?.dataset || {}, eda.catboost?.training?.split_protocol || {});
    renderDonutChart("label-chart", eda.catboost?.dataset?.label_distribution || {}, "label", "событий");
    renderVerticalChart("scenario-chart", eda.catboost?.dataset?.scenario_distribution || {}, "scenario", {
      limit: 8,
      palette: ["#8e5b2c", "#b37a43", "#c59158", "#d1a66f", "#8b3d2c", "#365c5a", "#5a7d7b", "#9e6d38"],
      labelFormatter: formatScenarioCompact,
    });
    renderCatboostSplit(eda.catboost?.training?.split_protocol || {});
    renderTopToolsByLabel(eda.catboost?.dataset?.top_tools_by_label || {});
    renderRuleLayer(eda.catboost?.rule_layer || {});
    renderDecisionExamples(eda.catboost?.sample_events || []);
    renderStageOneModelComparison(data?.evaluation?.model_metrics || []);
    renderCatboostParams(eda.catboost?.training?.best_params || {});
    renderCatboostMetricCurves(eda.catboost?.training?.models || []);
    renderFeatureImportanceChart(eda.catboost?.training?.feature_importance || data?.evaluation?.feature_importance || []);
    renderConfusionMatrix(
      eda.catboost?.training?.confusion_matrix ? [eda.catboost.training.confusion_matrix] : data?.evaluation?.model_metrics || []
    );
    renderStageOneScheme();
    renderGlinerOverview(eda.gliner || {});
    renderDonutChart("gliner-balance-chart", eda.gliner?.source_corpus?.request_safety || {}, "request_safety", "запросов");
    renderHorizontalRankChart("gliner-source-type-chart", eda.gliner?.source_corpus?.source_types || {}, "source_type", {
      limit: 8,
      palette: ["#365c5a", "#4c7875", "#5f8c89", "#78a4a1", "#8e5b2c", "#b37a43", "#c59158", "#d1a66f"],
    });
    renderLollipopChart("gliner-label-support-chart", eda.gliner?.source_corpus?.row_label_support || {}, "entity", {
      limit: 6,
      palette: ["#8b3d2c", "#a6573f", "#bf7354", "#d49073", "#365c5a", "#8e5b2c"],
    });
    renderVerticalChart("gliner-template-chart", eda.gliner?.source_corpus?.template_families || {}, "template", {
      limit: 8,
      palette: ["#8e5b2c", "#b37a43", "#d1a66f", "#365c5a", "#5f8c89", "#8b3d2c", "#bf7354", "#c59158"],
    });
    renderSplitComparison(eda.gliner?.splits || {});
    renderGlinerMetricCurves(eda.gliner?.evaluation || {});
    renderThresholdCurve(eda.gliner?.evaluation?.threshold_curve || []);
    renderGlinerLabelComparison(eda.gliner?.evaluation?.label_comparison || []);
    renderArchitecture(data || {});
    renderFinalImplementation();
  } catch (error) {
    const target = document.getElementById("catboost-overview");
    if (target) {
      target.innerHTML = `<article class="kpi-card"><strong>Не удалось загрузить данные дашборда</strong><p>${escapeHtml(
        error.message
      )}</p></article>`;
    }
  }
}

async function fetchJsonRequired(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`);
  }
  return response.json();
}

async function fetchJsonOptional(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) return null;
    return await response.json();
  } catch (error) {
    return null;
  }
}

function renderCatboostOverview(dataset, splitProtocol) {
  const target = document.getElementById("catboost-overview");
  if (!target) return;

  const scenarioCount = Object.keys(dataset.scenario_distribution || {}).length;
  const cards = [
    {
      label: "Всего событий",
      value: String(dataset.total_records || 0),
      note: "Лабораторный датасет MCP-событий для первого этапа защитного контура.",
    },
    {
      label: "Train / test",
      value: `${splitProtocol.train_rows || 0} / ${splitProtocol.test_rows || 0}`,
      note: "Разделение выборки для обучения и итоговой тестовой оценки.",
    },
    {
      label: "Типов сценариев",
      value: String(scenarioCount),
      note: "Безопасные, аномальные и вредоносные кейсы распределены по нескольким шаблонам поведения.",
    },
  ];

  target.innerHTML = cards
    .map(
      (card) => `
        <article class="kpi-card">
          <span class="kpi-label">${escapeHtml(card.label)}</span>
          <strong class="kpi-value">${escapeHtml(card.value)}</strong>
          <p class="kpi-note">${escapeHtml(card.note)}</p>
        </article>
      `
    )
    .join("");
}

function renderCatboostSplit(splitProtocol) {
  const target = document.getElementById("catboost-split-grid");
  if (!target) return;

  const steps = [
    {
      label: "Разбиение",
      value: splitProtocol.type || "StratifiedGroupKFold",
      note: "Train и test формировались с группировкой по session_id.",
    },
    {
      label: "Тестовая часть",
      value: `${splitProtocol.test_rows || 0} строк / ${splitProtocol.test_groups || 0} групп`,
      note: "Отдельная тестовая часть использовалась для итоговой оценки выбранной конфигурации.",
    },
  ];

  target.innerHTML = steps
    .map(
      (step) => `
        <article class="scheme-card">
          <span class="signal-label">${escapeHtml(step.label)}</span>
          <strong>${escapeHtml(step.value)}</strong>
          <p>${escapeHtml(step.note)}</p>
        </article>
      `
    )
    .join("");
}

function renderNumericProfile(dataset) {
  const target = document.getElementById("catboost-numeric-profile");
  if (!target) return;

  const byLabel = dataset.numeric_by_label || [];
  target.innerHTML = `
    <div class="comparison-row">
      <div class="comparison-title">
        <strong>Средний payload size</strong>
      </div>
      <div class="comparison-bars">
        ${byLabel
          .map(
            (row) => `
              <div class="comparison-bar-row" title="${escapeHtml(`${formatCategory(row.label, "label")}: ${Math.round(Number(row.avg_payload_size || 0))}`)}">
                <span>${escapeHtml(formatCategory(row.label, "label"))}</span>
                <div class="bar-track">
                  <div class="bar-fill ${barToneClass(row.label, "label")}" style="width: ${Math.min((Number(row.avg_payload_size || 0) / 6000) * 100, 100)}%"></div>
                </div>
                <strong>${Math.round(Number(row.avg_payload_size || 0))}</strong>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
    <div class="comparison-row">
      <div class="comparison-title">
        <strong>Среднее время ответа, мс</strong>
      </div>
      <div class="comparison-bars">
        ${byLabel
          .map(
            (row) => `
              <div class="comparison-bar-row" title="${escapeHtml(`${formatCategory(row.label, "label")}: ${Math.round(Number(row.avg_response_time_ms || 0))} мс`)}">
                <span>${escapeHtml(formatCategory(row.label, "label"))}</span>
                <div class="bar-track">
                  <div class="bar-fill ${barToneClass(row.label, "label")}" style="width: ${Math.min((Number(row.avg_response_time_ms || 0) / 2000) * 100, 100)}%"></div>
                </div>
                <strong>${Math.round(Number(row.avg_response_time_ms || 0))}</strong>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
    <div class="comparison-row">
      <div class="comparison-title">
        <strong>Средний risk score по классам</strong>
      </div>
      <div class="comparison-bars">
        ${byLabel
          .map(
            (row) => `
              <div class="comparison-bar-row" title="${escapeHtml(`${formatCategory(row.label, "label")}: ${Number(row.avg_risk_score || 0).toFixed(3)}`)}">
                <span>${escapeHtml(formatCategory(row.label, "label"))}</span>
                <div class="bar-track">
                  <div class="bar-fill ${barToneClass(row.label, "label")}" style="width: ${Number(row.avg_risk_score || 0) * 100}%"></div>
                </div>
                <strong>${Number(row.avg_risk_score || 0).toFixed(3)}</strong>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderTopToolsByLabel(topToolsByLabel) {
  const target = document.getElementById("catboost-top-tools");
  if (!target) return;

  target.innerHTML = `
    <div class="tool-columns">
      ${Object.entries(topToolsByLabel)
        .map(
          ([label, rows]) => `
            <article class="tool-column-card">
              <h4>${escapeHtml(formatCategory(label, "label"))}</h4>
              <div class="bar-list">
                ${rows
                  .map(
                    (row) => `
                      <div class="bar-item" ${tooltipAttr(`${row.tool}: ${row.count}`)}>
                        <div class="bar-meta">
                          <strong>${escapeHtml(row.tool)}</strong>
                          <span>${row.count}</span>
                        </div>
                        <div class="bar-track">
                          <div class="bar-fill ${barToneClass(label, "label")}" style="width: ${(Number(row.count) / Number(rows[0].count || 1)) * 100}%"></div>
                        </div>
                      </div>
                    `
                  )
                  .join("")}
              </div>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderRuleLayer(ruleLayer) {
  const target = document.getElementById("catboost-rule-layer");
  if (!target) return;

  const rules = ruleLayer.core_rules || [];
  target.innerHTML = `
    <div class="rule-layer-summary rule-layer-summary-single">
      <article class="rule-summary-card">
        <span class="kpi-label">Всего правил</span>
        <strong class="kpi-value">${Number(ruleLayer.total_rules || 0)}</strong>
        <p class="kpi-note">В библиотеке первого этапа используются блокирующие и предупреждающие rule-based проверки.</p>
      </article>
    </div>
    <p class="rule-layer-note">Ниже показаны ключевые правила, которые лучше всего иллюстрируют работу rule-based слоя на событиях первого этапа.</p>
    <div class="matrix-table-wrap">
      <table class="metrics-table rules-table">
        <thead>
          <tr>
            <th>Правило</th>
            <th>Тип</th>
            <th>Что фиксирует</th>
            <th>Срабатываний</th>
            <th>Пример</th>
          </tr>
        </thead>
        <tbody>
          ${rules
            .map(
              (rule) => `
                <tr ${tooltipAttr(`${rule.name}\n${rule.detects}\nСрабатываний: ${rule.coverage}`)}>
                  <td>${escapeHtml(rule.name)}</td>
                  <td><span class="inline-badge inline-badge-${escapeHtml(rule.severity)}">${escapeHtml(rule.severity)}</span></td>
                  <td>${escapeHtml(rule.detects)}</td>
                  <td>${Number(rule.coverage || 0)}</td>
                  <td>${escapeHtml(rule.example || "—")}</td>
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderDecisionExamples(rows) {
  const target = document.getElementById("catboost-decision-examples");
  if (!target || !rows.length) return;

  target.innerHTML = `
    <div class="decision-examples-layout">
      <div class="matrix-table-wrap">
        <table class="metrics-table decision-examples-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Решение</th>
              <th>Инструмент</th>
              <th>Сценарий</th>
              <th>Класс</th>
              <th>Риск</th>
            </tr>
          </thead>
          <tbody>
            ${rows
              .map(
                (row, index) => `
                  <tr class="example-row example-row-${escapeHtml(row.decision)} ${index === 0 ? "is-active" : ""}" data-example-index="${index}" ${tooltipAttr(`${formatDecision(row.decision)} | ${formatScenario(row.scenario_type)} | ${formatExampleRiskLabel(row)}`)}>
                    <td>${escapeHtml(row.id)}</td>
                    <td><span class="inline-badge inline-badge-${escapeHtml(row.decision)}">${escapeHtml(formatDecision(row.decision))}</span></td>
                    <td>${escapeHtml(row.tool_name)}</td>
                    <td>${escapeHtml(formatScenario(row.scenario_type))}</td>
                    <td>${escapeHtml(formatCategory(row.label, "label"))}</td>
                    <td>${escapeHtml(formatExampleRiskValue(row))}</td>
                  </tr>
                `
              )
              .join("")}
          </tbody>
        </table>
      </div>
      <article class="example-detail-card" id="catboost-example-detail"></article>
    </div>
  `;

  const detailTarget = document.getElementById("catboost-example-detail");
  const rowNodes = target.querySelectorAll(".example-row");

  const setActiveExample = (index) => {
    const row = rows[index];
    if (!row || !detailTarget) return;
    rowNodes.forEach((node) => node.classList.toggle("is-active", Number(node.dataset.exampleIndex) === index));
    detailTarget.innerHTML = `
      <div class="example-detail-tone example-detail-tone-${escapeHtml(row.decision)}"></div>
      <span class="signal-label">Событие ${escapeHtml(row.id)}</span>
      <h4>${escapeHtml(row.tool_name)}</h4>
      <div class="example-detail-meta">
        <span class="stage-pill decision-${escapeHtml(row.label)}">${escapeHtml(formatCategory(row.label, "label"))}</span>
        <span class="stage-pill decision-${escapeHtml(row.decision)}">${escapeHtml(formatDecision(row.decision))}</span>
      </div>
      <div class="detail-grid">
        <div><strong>Сценарий</strong><span>${escapeHtml(formatScenario(row.scenario_type))}</span></div>
        <div><strong>Размер запроса</strong><span>${Number(row.payload_size || 0)} bytes</span></div>
        <div><strong>Время ответа</strong><span>${Number(row.response_time_ms || 0)} ms</span></div>
        <div><strong>Оценка риска</strong><span>${escapeHtml(formatExampleRiskValue(row))}</span></div>
        <div><strong>Правила</strong><span>${row.rule_names?.length ? escapeHtml(row.rule_names.join(", ")) : "—"}</span></div>
      </div>
      <p class="decision-rationale">${escapeHtml(row.rationale || "—")}</p>
    `;
  };

  rowNodes.forEach((node) => {
    node.addEventListener("mouseenter", () => setActiveExample(Number(node.dataset.exampleIndex)));
    node.addEventListener("click", () => setActiveExample(Number(node.dataset.exampleIndex)));
  });

  setActiveExample(0);
}

function renderCatboostParams(params) {
  const target = document.getElementById("catboost-params");
  if (!target) return;

  const labels = [
    ["iterations", "iterations"],
    ["depth", "depth"],
    ["learning_rate", "learning rate"],
    ["l2_leaf_reg", "l2 leaf reg"],
    ["random_strength", "random strength"],
    ["bagging_temperature", "bagging temperature"],
  ];

  target.innerHTML = `
    <div class="param-grid">
      ${labels
        .map(
          ([key, label]) => `
            <div class="param-card">
              <span class="signal-label">${escapeHtml(label)}</span>
              <strong>${formatParamValue(params[key])}</strong>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function renderStageOneModelComparison(models) {
  const target = document.getElementById("catboost-model-table");
  if (!target) return;

  const priorityOrder = [
    "Rule-based baseline",
    "Logistic Regression",
    "SVM",
    "Decision Tree",
    "Random Forest",
    "LightGBM",
    "XGBoost",
    "CatBoost",
  ];

  const sorted = models
    .slice()
    .sort((left, right) => priorityOrder.indexOf(left.model) - priorityOrder.indexOf(right.model));

  target.innerHTML = sorted
    .map((model) => {
      const isBest = model.model === "CatBoost";
      return `
        <tr class="${isBest ? "metrics-row-best" : ""}" ${tooltipAttr(`${model.model}\nBalanced Accuracy: ${Number(model.balanced_accuracy || 0).toFixed(4)}\nMacro Precision: ${Number(model.macro_precision || 0).toFixed(4)}\nMacro Recall: ${Number(model.macro_recall || 0).toFixed(4)}\nPR-AUC OVR: ${Number(model.pr_auc_ovr || 0).toFixed(4)}\nROC-AUC OVR: ${Number(model.roc_auc_ovr || 0).toFixed(4)}`)}>
          <td>${escapeHtml(model.model || "—")}</td>
          <td>${Number(model.balanced_accuracy || 0).toFixed(4)}</td>
          <td>${Number(model.macro_precision || 0).toFixed(4)}</td>
          <td>${Number(model.macro_recall || 0).toFixed(4)}</td>
          <td>${Number(model.pr_auc_ovr || 0).toFixed(4)}</td>
          <td>${Number(model.roc_auc_ovr || 0).toFixed(4)}</td>
        </tr>
      `;
    })
    .join("");
}

function renderStageOneScheme() {
  const target = document.getElementById("stage1-scheme");
  if (!target) return;

  target.innerHTML = `
    <div class="mini-pipeline-grid">
      <article class="mini-pipeline-card">
        <span class="pipeline-step">01</span>
        <h4>Rule-based слой</h4>
        <p>Покрывает явные нарушения: приватные адреса, чувствительные пути и несовместимые client-server сочетания.</p>
      </article>
      <article class="mini-pipeline-card">
        <span class="pipeline-step">02</span>
        <h4>CatBoost</h4>
        <p>Оценивает риск по признакам события и устойчиво разделяет normal, anomalous и malicious сценарии.</p>
      </article>
      <article class="mini-pipeline-card">
        <span class="pipeline-step">03</span>
        <h4>Итог этапа</h4>
        <p>В рабочем контуре первый этап используется как быстрый фильтр перед semantic-stage анализом.</p>
      </article>
    </div>
  `;
}

function renderCatboostDeltaSummary(models) {
  const target = document.getElementById("catboost-delta-summary");
  if (!target || models.length < 2) return;

  const baseline = models[0];
  const tuned = models[1];
  const rows = [
    ["Balanced Accuracy", baseline.balanced_accuracy, tuned.balanced_accuracy],
    ["Macro Precision", baseline.macro_precision, tuned.macro_precision],
    ["Macro Recall", baseline.macro_recall, tuned.macro_recall],
    ["PR-AUC OVR", baseline.pr_auc_ovr, tuned.pr_auc_ovr],
    ["ROC-AUC OVR", baseline.roc_auc_ovr, tuned.roc_auc_ovr],
  ];

  target.innerHTML = rows
    .map(
      ([label, before, after]) => `
        <div class="comparison-row">
          <div class="comparison-title">
            <strong>${escapeHtml(label)}</strong>
            <span>${escapeHtml(formatDelta(before, after))}</span>
          </div>
          <div class="comparison-meta">
            <span>baseline: ${Number(before || 0).toFixed(4)}</span>
            <span>tuned: ${Number(after || 0).toFixed(4)}</span>
          </div>
        </div>
      `
    )
    .join("");
}

function renderMetricComparison(targetId, rows) {
  const target = document.getElementById(targetId);
  if (!target || !rows.length) return;

  const metricLabels = [
    ["balanced_accuracy", "Balanced Accuracy"],
    ["macro_precision", "Macro Precision"],
    ["macro_recall", "Macro Recall"],
    ["pr_auc_ovr", "PR-AUC OVR"],
    ["roc_auc_ovr", "ROC-AUC OVR"],
  ];

  target.innerHTML = metricLabels
    .map(([key, label]) => {
      const values = rows.map((row) => Number(row[key] || 0));
      const max = Math.max(...values, 1);
      return `
        <div class="comparison-row">
          <div class="comparison-title">
            <strong>${escapeHtml(label)}</strong>
          </div>
          <div class="comparison-bars">
            ${rows
              .map(
                (row, index) => `
                  <div class="comparison-bar-row" title="${escapeHtml(`${row.label}: ${Number(row[key] || 0).toFixed(4)}`)}">
                    <span>${escapeHtml(row.label)}</span>
                    <div class="bar-track">
                      <div class="bar-fill ${index === 0 ? "accent" : index === 1 ? "teal" : "safe"}" style="width: ${
                        (Number(row[key] || 0) / max) * 100
                      }%"></div>
                    </div>
                    <strong>${Number(row[key] || 0).toFixed(4)}</strong>
                  </div>
                `
              )
              .join("")}
          </div>
        </div>
      `;
    })
    .join("");
}

function renderBeforeAfterComparison(targetId, rows) {
  const target = document.getElementById(targetId);
  if (!target || !rows.length) return;

  target.innerHTML = buildBeforeAfterComparisonMarkup(rows, "До обучения", "После LoRA");
}

function buildBeforeAfterComparisonMarkup(rows, beforeLabel, afterLabel) {
  const max = Math.max(
    ...rows.flatMap((row) => [Number(row.before || 0), Number(row.after || 0)]),
    1
  );

  return rows
    .map(
      (row) => `
        <div class="comparison-row">
          <div class="comparison-title">
            <strong>${escapeHtml(row.label)}</strong>
            <span>${formatDelta(row.before, row.after)}</span>
          </div>
          <div class="comparison-bars">
            <div class="comparison-bar-row" title="${escapeHtml(`${beforeLabel}: ${Number(row.before || 0).toFixed(4)}`)}">
              <span>${escapeHtml(beforeLabel)}</span>
              <div class="bar-track">
                <div class="bar-fill accent" style="width: ${(Number(row.before || 0) / max) * 100}%"></div>
              </div>
              <strong>${Number(row.before || 0).toFixed(4)}</strong>
            </div>
            <div class="comparison-bar-row" title="${escapeHtml(`${afterLabel}: ${Number(row.after || 0).toFixed(4)}`)}">
              <span>${escapeHtml(afterLabel)}</span>
              <div class="bar-track">
                <div class="bar-fill teal" style="width: ${(Number(row.after || 0) / max) * 100}%"></div>
              </div>
              <strong>${Number(row.after || 0).toFixed(4)}</strong>
            </div>
          </div>
        </div>
      `
    )
    .join("");
}

function renderDeltaMetricListMarkup(rows, beforeLabel, afterLabel) {
  const deltaRows = rows.map((row) => ({
    ...row,
    delta: Number(row.after || 0) - Number(row.before || 0),
  }));
  const maxDelta = Math.max(...deltaRows.map((row) => Math.abs(row.delta)), 0.0001);

  return deltaRows
    .map(
      (row) => `
        <div class="comparison-row">
          <div class="comparison-title">
            <strong>${escapeHtml(row.label)}</strong>
            <span>${escapeHtml(formatDelta(row.before, row.after))}</span>
          </div>
          <div class="comparison-bars">
            <div class="comparison-bar-row" title="${escapeHtml(`${beforeLabel}: ${Number(row.before || 0).toFixed(4)} | ${afterLabel}: ${Number(row.after || 0).toFixed(4)}`)}">
              <span>Прирост tuned</span>
              <div class="bar-track">
                <div class="bar-fill teal" style="width: ${(Math.abs(row.delta) / maxDelta) * 100}%"></div>
              </div>
              <strong>${row.delta >= 0 ? "+" : ""}${row.delta.toFixed(4)}</strong>
            </div>
          </div>
          <div class="comparison-meta">
            <span>baseline: ${Number(row.before || 0).toFixed(4)}</span>
            <span>tuned: ${Number(row.after || 0).toFixed(4)}</span>
          </div>
        </div>
      `
    )
    .join("");
}

function renderGlinerOverview(gliner) {
  const target = document.getElementById("gliner-overview");
  if (!target) return;

  const source = gliner.source_corpus || {};
  const after = gliner.evaluation?.after || {};
  const threshold = gliner.evaluation?.after_validation?.threshold ?? 0.99;
  const cards = [
    {
      label: "Строк в исходном корпусе",
      value: String(source.rows || 0),
      note: "Исходный suspicious MCP-корпус до разбиения на train, validation и test.",
    },
    {
      label: "Типов источников",
      value: String(Object.keys(source.source_types || {}).length),
      note: "В корпус включены natural language, shell, JSON, YAML, MCP request и code-like форматы.",
    },
    {
      label: "Порог для тестовой оценки",
      value: String(threshold),
      note: "Итоговая тестовая оценка рассчитывалась для threshold = 0.99.",
    },
    {
      label: "Gated F1 на тесте",
      value: `${Number(after.gated_f1 || 0).toFixed(4)}`,
      note: "Итоговая span-level метрика на тестовой части после LoRA-дообучения.",
    },
  ];

  target.innerHTML = cards
    .map(
      (card) => `
        <article class="kpi-card">
          <span class="kpi-label">${escapeHtml(card.label)}</span>
          <strong class="kpi-value">${escapeHtml(card.value)}</strong>
          <p class="kpi-note">${escapeHtml(card.note)}</p>
        </article>
      `
    )
    .join("");
}

function renderSplitComparison(splits) {
  const target = document.getElementById("gliner-split-chart");
  if (!target) return;

  const rows = Object.entries(splits).map(([name, values]) => ({
    label: name,
    rows: values.rows,
    safe: values.safe,
    suspicious: values.suspicious,
  }));

  target.innerHTML = rows
    .map(
      (row) => `
        <div class="comparison-row">
          <div class="comparison-title">
            <strong>${escapeHtml(row.label)}</strong>
            <span>${row.rows} строк</span>
          </div>
          <div class="comparison-bars">
                  <div class="comparison-bar-row" ${tooltipAttr(`${row.label} safe: ${row.safe}`)}>
              <span>safe</span>
              <div class="bar-track">
                <div class="bar-fill safe" style="width: ${(Number(row.safe || 0) / Number(row.rows || 1)) * 100}%"></div>
              </div>
              <strong>${row.safe}</strong>
            </div>
                  <div class="comparison-bar-row" ${tooltipAttr(`${row.label} suspicious: ${row.suspicious}`)}>
              <span>suspicious</span>
              <div class="bar-track">
                <div class="bar-fill danger" style="width: ${(Number(row.suspicious || 0) / Number(row.rows || 1)) * 100}%"></div>
              </div>
              <strong>${row.suspicious}</strong>
            </div>
          </div>
        </div>
      `
    )
    .join("");
}

function renderThresholdCurve(rows) {
  const target = document.getElementById("gliner-threshold-chart");
  if (!target || !rows.length) return;

  const best = rows.reduce((winner, row) => (Number(row.gated_f1 || 0) > Number(winner.gated_f1 || 0) ? row : winner), rows[0]);
  const chartRows = rows.map((row, index) => ({
    x: index + 1,
    threshold: Number(row.threshold),
    series: {
      "Request F1": Number(row.request_f1 || 0),
      "Gated F1": Number(row.gated_f1 || 0),
    },
  }));

  target.innerHTML = renderLineChartMarkup({
    summary: `
      <div class="threshold-highlight">
        <strong>Лучший threshold: ${Number(best.threshold).toFixed(2)}</strong>
        <span>Request F1: ${Number(best.request_f1 || 0).toFixed(4)} · Gated F1: ${Number(best.gated_f1 || 0).toFixed(4)}</span>
      </div>
    `,
    xFormatter: (value) => {
      const sourceRow = chartRows[Math.max(0, Math.min(chartRows.length - 1, Math.round(Number(value)) - 1))];
      return sourceRow ? sourceRow.threshold.toFixed(2) : String(value);
    },
    pointTitleFormatter: ({ x, seriesName, value }) => {
      const sourceRow = chartRows[Math.max(0, Math.min(chartRows.length - 1, Math.round(Number(x)) - 1))];
      if (!sourceRow) {
        return `${seriesName}\nvalue ${Number(value).toFixed(4)}`;
      }
      return [
        `${seriesName}`,
        `threshold: ${Number(sourceRow.threshold).toFixed(2)}`,
        `request F1: ${Number(sourceRow.series["Request F1"] || 0).toFixed(4)}`,
        `gated F1: ${Number(sourceRow.series["Gated F1"] || 0).toFixed(4)}`,
      ].join("\n");
    },
    pointLabelOffsetFormatter: ({ seriesIndex }) => (seriesIndex === 0 ? -12 : 18),
    showSummary: false,
    rows: chartRows,
  });
}

function renderGlinerLabelComparison(rows) {
  const target = document.getElementById("gliner-label-comparison");
  if (!target) return;

  const sorted = rows.slice().sort((left, right) => Number(right.after_f1 || 0) - Number(left.after_f1 || 0));
  target.innerHTML = `
    <div class="entity-quality-grid">
      ${sorted
        .map((row) => {
          const tooltip = [
            formatCategory(row.label, "entity"),
            `Precision: ${Number(row.after_precision || 0).toFixed(4)}`,
            `Recall: ${Number(row.after_recall || 0).toFixed(4)}`,
            `F1: ${Number(row.after_f1 || 0).toFixed(4)}`,
          ].join("\n");
          return `
            <div class="entity-quality-row" ${tooltipAttr(tooltip)}>
              <div class="entity-quality-head">
                <strong>${escapeHtml(formatCategory(row.label, "entity"))}</strong>
                <span>${Number(row.after_f1 || 0).toFixed(4)}</span>
              </div>
              <div class="bar-track entity-quality-track">
                <div class="bar-fill teal" style="width:${Number(row.after_f1 || 0) * 100}%"></div>
              </div>
              <div class="entity-quality-meta">
                <span>P ${Number(row.after_precision || 0).toFixed(4)}</span>
                <span>R ${Number(row.after_recall || 0).toFixed(4)}</span>
                <span>F1 ${Number(row.after_f1 || 0).toFixed(4)}</span>
              </div>
            </div>
          `;
        })
        .join("")}
    </div>
  `;
}

function renderCatboostMetricCurves(models) {
  const baselineTarget = document.getElementById("catboost-baseline-curve");
  const tunedTarget = document.getElementById("catboost-tuned-curve");
  const baseline = models[0];
  const tuned = models[1];
  if (!baseline || !tuned) return;

  const metricRows = [
    { label: "Balanced Accuracy", before: baseline.balanced_accuracy, after: tuned.balanced_accuracy },
    { label: "Macro Precision", before: baseline.macro_precision, after: tuned.macro_precision },
    { label: "Macro Recall", before: baseline.macro_recall, after: tuned.macro_recall },
    { label: "PR-AUC OVR", before: baseline.pr_auc_ovr, after: tuned.pr_auc_ovr },
    { label: "ROC-AUC OVR", before: baseline.roc_auc_ovr, after: tuned.roc_auc_ovr },
  ];

  if (baselineTarget) {
    baselineTarget.innerHTML = buildCatboostSmallMultiples(metricRows);
  }

  if (tunedTarget) {
    tunedTarget.innerHTML = buildCatboostDeltaOverview(metricRows);
  }
}

function buildCatboostSmallMultiples(rows) {
  const featured = rows.filter((row) =>
    ["Macro Precision", "Macro Recall", "PR-AUC OVR", "ROC-AUC OVR"].includes(row.label)
  );
  return `
    <div class="chart-shell">
      <div class="mini-chart-grid">
        ${featured
          .map(
            (row) => `
              <div class="mini-chart-card">
                <h4>${escapeHtml(row.label)}</h4>
                <div class="mini-chart-body">
                  ${renderLineChartMarkup({
                    rows: [
                      { x: 1, series: { Metric: Number(row.before || 0) } },
                      { x: 2, series: { Metric: Number(row.after || 0) } },
                    ],
                    xFormatter: (value) => (Number(value) === 1 ? "Baseline" : "Tuned"),
                    pointTitleFormatter: ({ x, value }) =>
                      `${row.label}\n${Number(x) === 1 ? "Baseline" : "Tuned"}: ${Number(value).toFixed(4)}`,
                    yDomain: {
                      min: Math.min(Number(row.before || 0), Number(row.after || 0)) - 0.01,
                      max: Math.max(Number(row.before || 0), Number(row.after || 0)) + 0.01,
                    },
                    compact: false,
                    showSummary: false,
                    showLegend: false,
                  })}
                </div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function buildCatboostDeltaOverview(rows) {
  const deltas = rows.map((row, index) => ({
    label: row.label,
    x: index + 1,
    delta: Number(row.after || 0) - Number(row.before || 0),
    before: Number(row.before || 0),
    after: Number(row.after || 0),
  }));
  const maxDelta = Math.max(...deltas.map((row) => row.delta), 0.001);

  return `
    <div class="chart-shell">
      <div class="delta-feature-card">
        <h4>Прирост tuned по метрикам</h4>
        ${renderLineChartMarkup({
          rows: deltas.map((row) => ({
            x: row.x,
            series: { Delta: row.delta },
          })),
          xFormatter: (value) => {
            const row = deltas.find((item) => item.x === Number(value));
            if (!row) return String(value);
            return row.label
              .replace("Balanced Accuracy", "BA")
              .replace("Macro Precision", "Precision")
              .replace("Macro Recall", "Recall");
          },
          pointTitleFormatter: ({ x, value }) => {
            const row = deltas.find((item) => item.x === Number(x));
            if (!row) return `Delta: ${Number(value).toFixed(4)}`;
            return [
              row.label,
              `baseline: ${row.before.toFixed(4)}`,
              `tuned: ${row.after.toFixed(4)}`,
              `delta: ${value >= 0 ? "+" : ""}${Number(value).toFixed(4)}`,
            ].join("\n");
          },
          pointLabelFormatter: ({ value }) => `${value >= 0 ? "+" : ""}${Number(value).toFixed(4)}`,
          yDomain: {
            min: 0,
            max: maxDelta + 0.003,
          },
          showSummary: false,
          showLegend: false,
        })}
      </div>
      <div class="comparison-list comparison-list-compact">
        ${deltas
          .map(
            (row) => `
              <div class="comparison-row comparison-row-tight">
                <div class="comparison-title">
                  <strong>${escapeHtml(row.label)}</strong>
                  <span>${row.delta >= 0 ? "+" : ""}${row.delta.toFixed(4)}</span>
                </div>
                <div class="comparison-meta">
                  <span>baseline: ${row.before.toFixed(4)}</span>
                  <span>tuned: ${row.after.toFixed(4)}</span>
                </div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderGlinerMetricCurves(evaluation) {
  const requestTarget = document.getElementById("gliner-request-curve");
  const spanTarget = document.getElementById("gliner-span-curve");
  if (requestTarget) {
    const requestMetrics = [
      { key: "precision", short: "Precision" },
      { key: "recall", short: "Recall" },
      { key: "f1", short: "F1" },
      { key: "accuracy", short: "Accuracy" },
    ];
    requestTarget.innerHTML = renderMultiStageMetricCurve(requestMetrics, [
      { label: "До обучения", values: evaluation.before || {} },
      { label: "После LoRA", values: evaluation.after || {} },
    ]);
  }

  if (spanTarget) {
    const spanMetrics = [
      { key: "gated_precision", short: "Gated P" },
      { key: "gated_recall", short: "Gated R" },
      { key: "gated_f1", short: "Gated F1" },
    ];
    spanTarget.innerHTML = renderMultiStageMetricCurve(spanMetrics, [
      { label: "До обучения", values: evaluation.before || {} },
      { label: "После LoRA", values: evaluation.after || {} },
    ]);
  }
}

function renderSingleSeriesMetricCurve(metricKeys, label, values, yDomain = null) {
  const rows = metricKeys.map((metric, index) => ({
    x: index + 1,
    series: {
      [label]: Number(values?.[metric.key] || 0),
    },
  }));

  return renderLineChartMarkup({
    rows,
    xFormatter: (value) => metricKeys[Math.max(0, Math.min(metricKeys.length - 1, Math.round(value) - 1))].short,
    yDomain,
    pointTitleFormatter: ({ x, seriesName, value }) => {
      const metric = metricKeys[Math.max(0, Math.min(metricKeys.length - 1, Math.round(x) - 1))];
      return `${seriesName}\n${metric.short}: ${Number(value).toFixed(4)}`;
    },
  });
}

function renderMultiStageMetricCurve(metricKeys, seriesRows) {
  const rows = metricKeys.map((metric, index) => ({
    x: index + 1,
    series: Object.fromEntries(seriesRows.map((row) => [row.label, Number(row.values?.[metric.key] || 0)])),
  }));

  return renderLineChartMarkup({
    rows,
    xFormatter: (value) => metricKeys[Math.max(0, Math.min(metricKeys.length - 1, Math.round(value) - 1))].short,
    pointTitleFormatter: ({ x, seriesName, value }) => {
      const metric = metricKeys[Math.max(0, Math.min(metricKeys.length - 1, Math.round(x) - 1))];
      return `${seriesName}\n${metric.short}: ${Number(value).toFixed(4)}`;
    },
    pointLabelOffsetFormatter: ({ seriesIndex }) => (seriesIndex === 0 ? -12 : 18),
  });
}

function renderFinalImplementation() {
  const target = document.getElementById("final-implementation");
  if (!target) return;

  target.innerHTML = `
    <div class="comparison-row comparison-row-tight">
      <div class="comparison-title">
        <strong>Рабочий стенд</strong>
      </div>
      <p class="kpi-note">GitHub Pages, serverless API в Yandex Cloud и общий дашборд собирают итоговую демонстрацию проекта.</p>
    </div>
  `;
}

function renderDonutChart(targetId, values, type, centerLabel = "") {
  const target = document.getElementById(targetId);
  if (!target) return;

  const entries = Object.entries(values).sort((a, b) => Number(b[1]) - Number(a[1]));
  const total = entries.reduce((sum, [, value]) => sum + Number(value), 0);
  if (!entries.length || total === 0) {
    target.innerHTML = '<div class="empty-state compact-empty">Данные недоступны.</div>';
    return;
  }

  const emphasizeLegendTotal = targetId === "label-chart" || targetId === "gliner-balance-chart";

  const circumference = 2 * Math.PI * 44;
  let offset = 0;
  const segments = entries
    .map(([key, value]) => {
      const share = Number(value) / total;
      const stroke = circumference * share;
      const segment = `
        <circle
          class="donut-ring-segment"
          cx="60"
          cy="60"
          r="44"
          stroke="${chartColor(key, type)}"
          stroke-dasharray="${stroke} ${circumference - stroke}"
          stroke-dashoffset="${-offset}"
          ${tooltipAttr(`${formatCategory(key, type)}: ${value} (${(share * 100).toFixed(1)}%)`)}
        ></circle>
      `;
      offset += stroke;
      return segment;
    })
    .join("");

  target.innerHTML = `
    <div class="chart-shell chart-shell-donut">
      <div class="donut-visual">
        <svg viewBox="0 0 120 120" class="donut-chart" aria-hidden="true">
          <circle class="donut-ring-bg" cx="60" cy="60" r="44"></circle>
          ${segments}
        </svg>
        ${
          emphasizeLegendTotal
            ? ""
            : `<div class="donut-center">
          <strong>${total}</strong>
          <span>${escapeHtml(centerLabel)}</span>
        </div>`
        }
      </div>
      <div class="chart-legend">
        ${
          emphasizeLegendTotal
            ? `<div class="legend-total">
              <strong>${total}</strong>
              <span>${escapeHtml(centerLabel)}</span>
            </div>`
            : ""
        }
        ${entries
          .map(([key, value]) => {
            const share = ((Number(value) / total) * 100).toFixed(1);
            return `
              <div class="legend-item">
                <span class="legend-swatch" style="background:${chartColor(key, type)}"></span>
                <strong>${escapeHtml(formatCategory(key, type))}</strong>
                <span>${value} (${share}%)</span>
              </div>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}

function renderVerticalChart(targetId, values, type, options = {}) {
  const target = document.getElementById(targetId);
  if (!target) return;

  const entries = Object.entries(values)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, options.limit || 6);
  if (!entries.length) {
    target.innerHTML = '<div class="empty-state compact-empty">Данные недоступны.</div>';
    return;
  }

  const palette = options.palette || [];
  const max = Math.max(...entries.map(([, value]) => Number(value)), 1);
  target.innerHTML = `
    <div class="chart-shell">
      <div class="vbar-chart">
        ${entries
          .map(([key, value], index) => {
            const height = Math.max((Number(value) / max) * 100, 6);
            const fillColor = palette[index] || chartColor(key, type);
            const label = options.labelFormatter ? options.labelFormatter(key) : formatCategory(key, type);
            return `
              <div class="vbar-item" ${tooltipAttr(`${formatCategory(key, type)}: ${value}`)}>
                <div class="vbar-value">${value}</div>
                <div class="vbar-track">
                  <div class="vbar-fill" style="height:${height}%; background:${fillColor}"></div>
                </div>
                <div class="vbar-label">${escapeHtml(label)}</div>
              </div>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}

function renderHorizontalRankChart(targetId, values, type, options = {}) {
  const target = document.getElementById(targetId);
  if (!target) return;

  const entries = Object.entries(values)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, options.limit || 8);
  if (!entries.length) {
    target.innerHTML = '<div class="empty-state compact-empty">Данные недоступны.</div>';
    return;
  }

  const palette = options.palette || [];
  const max = Math.max(...entries.map(([, value]) => Number(value)), 1);

  target.innerHTML = `
    <div class="chart-shell">
      <div class="ranked-chart">
        ${entries
          .map(([key, value], index) => {
            const fillColor = palette[index] || chartColor(key, type);
            return `
              <div class="ranked-row" ${tooltipAttr(`${formatCategory(key, type)}: ${value}`)}>
                <div class="ranked-head">
                  <strong>${escapeHtml(formatCategory(key, type))}</strong>
                  <span>${value}</span>
                </div>
                <div class="ranked-track">
                  <div class="ranked-fill" style="width:${(Number(value) / max) * 100}%; background:${fillColor}"></div>
                </div>
              </div>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}

function renderLollipopChart(targetId, values, type, options = {}) {
  const target = document.getElementById(targetId);
  if (!target) return;

  const entries = Object.entries(values)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, options.limit || 6);
  if (!entries.length) {
    target.innerHTML = '<div class="empty-state compact-empty">Данные недоступны.</div>';
    return;
  }

  const palette = options.palette || [];
  const max = Math.max(...entries.map(([, value]) => Number(value)), 1);

  target.innerHTML = `
    <div class="chart-shell">
      <div class="lollipop-chart">
        ${entries
          .map(([key, value], index) => {
            const fillColor = palette[index] || chartColor(key, type);
            return `
              <div class="lollipop-row" ${tooltipAttr(`${formatCategory(key, type)}: ${value}`)}>
                <div class="lollipop-label">${escapeHtml(formatCategory(key, type))}</div>
                <div class="lollipop-axis">
                  <div class="lollipop-line"></div>
                  <div class="lollipop-dot" style="left: calc(${(Number(value) / max) * 100}% - 9px); background:${fillColor}"></div>
                </div>
                <div class="lollipop-value">${value}</div>
              </div>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}

function renderFeatureImportanceChart(features) {
  const top = features.slice(0, 6).map((item) => [cleanFeatureName(item.feature), Number(item.importance)]);
  renderVerticalChartFromPairs("feature-chart", top, { color: "var(--teal)" });
}

function renderLeaderboardChart(models) {
  const sorted = models
    .slice()
    .sort((a, b) => Number(b.pr_auc_ovr) - Number(a.pr_auc_ovr))
    .slice(0, 6)
    .map((item) => [item.model, Number(item.pr_auc_ovr)]);
  renderVerticalChartFromPairs("leaderboard-chart", sorted, { color: "var(--accent)" });
}

function renderVerticalChartFromPairs(targetId, pairs, options = {}) {
  const target = document.getElementById(targetId);
  if (!target) return;
  if (!pairs.length) {
    target.innerHTML = '<div class="empty-state compact-empty">Данные недоступны.</div>';
    return;
  }
  const max = Math.max(...pairs.map(([, value]) => Number(value)), 1);
  const color = options.color || "var(--accent)";
  target.innerHTML = `
    <div class="chart-shell">
      <div class="vbar-chart">
        ${pairs
          .map(
            ([label, value]) => `
              <div class="vbar-item" ${tooltipAttr(`${label}: ${Number(value) < 1 ? Number(value).toFixed(4) : Math.round(Number(value))}`)}>
                <div class="vbar-value">${Number(value) < 1 ? Number(value).toFixed(4) : Math.round(Number(value))}</div>
                <div class="vbar-track">
                  <div class="vbar-fill" style="height:${Math.max((Number(value) / max) * 100, 6)}%; background:${color}"></div>
                </div>
                <div class="vbar-label">${escapeHtml(label)}</div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderLineChartMarkup({
  rows,
  xFormatter,
  pointTitleFormatter,
  pointLabelFormatter = null,
  pointLabelOffsetFormatter = null,
  yDomain = null,
  summary = "",
  compact = false,
  showSummary = !compact,
  showLegend = !compact,
}) {
  if (!rows.length) {
    return '<div class="empty-state compact-empty">Данные недоступны.</div>';
  }

  const width = compact ? 320 : 520;
  const height = compact ? 180 : 240;
  const padding = compact ? { top: 18, right: 14, bottom: 34, left: 32 } : { top: 20, right: 18, bottom: 38, left: 38 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  const xValues = rows.map((row) => row.x);
  const seriesNames = Object.keys(rows[0].series);
  const yValues = rows.flatMap((row) => Object.values(row.series).map(Number));
  const rawMin = yDomain ? Number(yDomain.min) : Math.min(...yValues);
  const rawMax = yDomain ? Number(yDomain.max) : Math.max(...yValues);
  const rawRange = rawMax - rawMin;
  const paddingRatio = rawRange > 0 ? 0.12 : 0.05;
  const yPadding = rawRange > 0 ? rawRange * paddingRatio : Math.max(rawMax * paddingRatio, 0.02);
  const yMin = Math.max(0, rawMin - yPadding);
  const yMax = rawMax + yPadding;
  const yRange = yMax - yMin || 1;
  const xMin = Math.min(...xValues);
  const xMax = Math.max(...xValues);
  const xRange = xMax - xMin || 1;

  const palette = ["var(--accent)", "var(--teal)", "var(--safe)", "var(--warn)", "var(--danger)"];
  const seriesMarkup = seriesNames
    .map((seriesName, index) => {
      const color = palette[index % palette.length];
      const points = rows
        .map((row) => {
          const x = padding.left + ((row.x - xMin) / xRange) * plotWidth;
          const y = padding.top + plotHeight - ((Number(row.series[seriesName]) - yMin) / yRange) * plotHeight;
          return `${x},${y}`;
        })
        .join(" ");
      const dots = rows
        .map((row) => {
          const x = padding.left + ((row.x - xMin) / xRange) * plotWidth;
          const y = padding.top + plotHeight - ((Number(row.series[seriesName]) - yMin) / yRange) * plotHeight;
          const title = pointTitleFormatter
            ? pointTitleFormatter({ x: row.x, seriesName, value: Number(row.series[seriesName]) })
            : `${seriesName}\n${xFormatter(row.x)}: ${Number(row.series[seriesName]).toFixed(4)}`;
          const pointLabel = pointLabelFormatter
            ? pointLabelFormatter({ x: row.x, seriesName, value: Number(row.series[seriesName]) })
            : Number(row.series[seriesName]).toFixed(4);
          const pointLabelOffset = pointLabelOffsetFormatter
            ? pointLabelOffsetFormatter({
                x: row.x,
                seriesName,
                value: Number(row.series[seriesName]),
                seriesIndex: index,
              })
            : -10;
          return `
            <circle cx="${x}" cy="${y}" r="${compact ? 4 : 4.5}" fill="${color}"></circle>
            <circle cx="${x}" cy="${y}" r="${compact ? 11 : 12}" fill="transparent" stroke="transparent" pointer-events="all" class="chart-hit-circle" ${tooltipAttr(title)}></circle>
            <text x="${x}" y="${y + pointLabelOffset}" text-anchor="middle" class="line-point-value">${escapeHtml(pointLabel)}</text>
          `;
        })
        .join("");
      return `<polyline fill="none" stroke="${color}" stroke-width="3" points="${points}"></polyline>${dots}`;
    })
    .join("");

  const xLabels = rows
      .map((row) => {
        const x = padding.left + ((row.x - xMin) / xRange) * plotWidth;
        return `<text x="${x}" y="${height - 10}" text-anchor="middle" class="line-axis-label">${escapeHtml(xFormatter(row.x))}</text>`;
      })
      .join("");

  const summaryRows = rows
    .map((row) => {
      const values = seriesNames
        .map((seriesName) => `${seriesName}: ${Number(row.series[seriesName]).toFixed(4)}`)
        .join(" · ");
      return `<div class="metric-inline-row"><strong>${escapeHtml(xFormatter(row.x))}</strong><span>${escapeHtml(values)}</span></div>`;
    })
    .join("");

  return `
    <div class="chart-shell">
      ${summary}
      <svg viewBox="0 0 ${width} ${height}" class="line-chart" aria-hidden="true">
        <line x1="${padding.left}" y1="${padding.top + plotHeight}" x2="${width - padding.right}" y2="${padding.top + plotHeight}" class="line-axis"></line>
        <line x1="${padding.left}" y1="${padding.top}" x2="${padding.left}" y2="${padding.top + plotHeight}" class="line-axis"></line>
        ${seriesMarkup}
        ${xLabels}
      </svg>
      ${showSummary ? `<div class="metric-inline-list">${summaryRows}</div>` : ""}
      ${showLegend ? `<div class="chart-legend compact-legend">
        ${seriesNames
          .map(
            (name, index) => `
              <div class="legend-item">
                <span class="legend-swatch" style="background:${palette[index % palette.length]}"></span>
                <strong>${escapeHtml(name)}</strong>
              </div>
            `
          )
          .join("")}
      </div>` : ""}
    </div>
  `;
}

function renderGroupedComparisonChartMarkup(rows, options) {
  if (!rows.length) {
    return '<div class="empty-state compact-empty">Данные недоступны.</div>';
  }
  const max = Math.max(
    ...rows.flatMap((row) => [Number(row[options.leftKey] || 0), Number(row[options.rightKey] || 0)]),
    1
  );

  return `
    <div class="chart-shell">
      <div class="grouped-bars">
        ${rows
          .map(
            (row) => `
              <div class="grouped-bar-row" ${tooltipAttr(`${formatCategory(row.label, options.type)} | ${options.leftLabel}: ${Number(row[options.leftKey] || 0).toFixed(4)} | ${options.rightLabel}: ${Number(row[options.rightKey] || 0).toFixed(4)}`)}>
                <div class="grouped-bar-label">${escapeHtml(formatCategory(row.label, options.type))}</div>
                <div class="grouped-bar-columns">
                  <div class="grouped-bar-track">
                    <div class="grouped-bar-fill" style="width:${(Number(row[options.leftKey] || 0) / max) * 100}%; background:var(--accent)"></div>
                  </div>
                  <span>${Number(row[options.leftKey] || 0).toFixed(4)}</span>
                  <div class="grouped-bar-track">
                    <div class="grouped-bar-fill" style="width:${(Number(row[options.rightKey] || 0) / max) * 100}%; background:var(--teal)"></div>
                  </div>
                  <span>${Number(row[options.rightKey] || 0).toFixed(4)}</span>
                </div>
              </div>
            `
          )
          .join("")}
      </div>
      <div class="chart-legend compact-legend">
        <div class="legend-item"><span class="legend-swatch" style="background:var(--accent)"></span><strong>${escapeHtml(options.leftLabel)}</strong></div>
        <div class="legend-item"><span class="legend-swatch" style="background:var(--teal)"></span><strong>${escapeHtml(options.rightLabel)}</strong></div>
      </div>
    </div>
  `;
}

function chartColor(key, type) {
  if (type === "label") {
    return {
      normal: "#2f6e58",
      anomalous: "#b4822a",
      malicious: "#b9684b",
    }[key] || "#8e5b2c";
  }
  if (type === "decision") {
    return {
      allow: "#2f6e58",
      warn: "#b4822a",
      block: "#b9684b",
    }[key] || "#8e5b2c";
  }
  if (type === "request_safety") {
    return {
      safe: "#2f6e58",
      suspicious: "#b9684b",
    }[key] || "#8e5b2c";
  }
  return "#8e5b2c";
}

function renderArchitecture(data) {
  const target = document.getElementById("architecture-grid");
  if (!target) return;

  const scheme = data.evaluation?.summary?.current_scheme || "Rules + CatBoost";
  const cards = [
    {
      title: "Текстовый запрос",
      text: "Текст запроса преобразуется в MCP event.",
    },
    {
      title: "Rules + CatBoost",
      text: `Контур ${scheme} проверяет правила и признаки события.`,
    },
    {
      title: "GLiNER + LoRA",
      text: "Semantic-stage включается только для подозрительных случаев.",
    },
    {
      title: "Итоговое решение",
      text: "Система возвращает итоговое решение и объяснение.",
    },
  ];

  target.innerHTML = `
    <div class="architecture-shell">
      <div class="architecture-edge-row architecture-edge-row-top">
        <article class="architecture-edge-card">
          <span class="signal-label">Источник</span>
          <strong>Агент / MCP-клиент</strong>
        </article>
      </div>
      <div class="architecture-main-row">
        ${cards
          .map(
            (card, index) => `
              <article class="pipeline-card architecture-main-card">
                <span class="pipeline-step">${String(index + 1).padStart(2, "0")}</span>
                <h3>${escapeHtml(card.title)}</h3>
                <p>${escapeHtml(card.text)}</p>
              </article>
              ${index < cards.length - 1 ? '<span class="architecture-arrow" aria-hidden="true">→</span>' : ""}
            `
          )
          .join("")}
      </div>
      <div class="architecture-edge-row architecture-edge-row-bottom">
        <article class="architecture-edge-card">
          <span class="signal-label">Назначение</span>
          <strong>MCP-сервер и внешние инструменты</strong>
        </article>
        <article class="architecture-edge-card">
          <span class="signal-label">Артефакты</span>
          <strong>Логи, датасет и дашборд</strong>
        </article>
      </div>
    </div>
  `;
}

function renderBarList(targetId, values, type) {
  const target = document.getElementById(targetId);
  if (!target) return;

  const entries = Object.entries(values).sort((a, b) => Number(b[1]) - Number(a[1]));
  const max = Math.max(...entries.map(([, value]) => Number(value)), 1);
  const total = entries.reduce((sum, [, value]) => sum + Number(value), 0);

  target.innerHTML = entries
    .map(([key, value]) => {
      const width = (Number(value) / max) * 100;
      const share = total ? ((Number(value) / total) * 100).toFixed(1) : "0.0";
      return `
        <div class="bar-item" title="${escapeHtml(`${formatCategory(key, type)}: ${value} (${share}%)`)}">
          <div class="bar-meta">
            <strong>${escapeHtml(formatCategory(key, type))}</strong>
            <span>${value} · ${share}%</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill ${barToneClass(key, type)}" style="width: ${width}%"></div>
          </div>
        </div>
      `;
    })
    .join("");
}

function renderLeaderboard(models) {
  const target = document.getElementById("leaderboard-chart");
  const sorted = models.slice().sort((a, b) => Number(b.pr_auc_ovr) - Number(a.pr_auc_ovr)).slice(0, 6);
  const max = Math.max(...sorted.map((item) => Number(item.pr_auc_ovr)), 1);
  target.innerHTML = sorted
    .map(
      (item) => `
        <div class="bar-item" title="${escapeHtml(`${item.model}: ${Number(item.pr_auc_ovr).toFixed(4)}`)}">
          <div class="bar-meta">
            <strong>${escapeHtml(item.model)}</strong>
            <span>${Number(item.pr_auc_ovr).toFixed(4)}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill accent" style="width: ${(Number(item.pr_auc_ovr) / max) * 100}%"></div>
          </div>
        </div>
      `
    )
    .join("");
}

function renderFeatureImportance(features) {
  const target = document.getElementById("feature-chart");
  const top = features.slice(0, 6);
  const max = Math.max(...top.map((item) => Number(item.importance)), 1);
  target.innerHTML = top
    .map(
      (item) => `
        <div class="bar-item" title="${escapeHtml(`${cleanFeatureName(item.feature)}: ${Number(item.importance).toFixed(4)}`)}">
          <div class="bar-meta">
            <strong>${escapeHtml(cleanFeatureName(item.feature))}</strong>
            <span>${Number(item.importance).toFixed(4)}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill teal" style="width: ${(Number(item.importance) / max) * 100}%"></div>
          </div>
        </div>
      `
    )
    .join("");
}

function renderModelTable(models, targetId = "model-table") {
  const target = document.getElementById(targetId);
  if (!target) return;
  const sorted = models.slice().sort((a, b) => Number(b.pr_auc_ovr) - Number(a.pr_auc_ovr));
  target.innerHTML = sorted
    .map(
      (model) => `
        <tr>
          <td>${escapeHtml(model.model || model.label)}</td>
          <td>${Number(model.balanced_accuracy).toFixed(4)}</td>
          <td>${Number(model.macro_precision).toFixed(4)}</td>
          <td>${Number(model.macro_recall).toFixed(4)}</td>
          <td>${Number(model.pr_auc_ovr).toFixed(4)}</td>
          <td>${Number(model.roc_auc_ovr).toFixed(4)}</td>
        </tr>
      `
    )
    .join("");
}

function renderDecisionMatrix(matrix) {
  const target = document.getElementById("decision-matrix");
  if (!target) return;

  const normalized = {
    normal: { allow: 0, warn: 0, block: 0 },
    anomalous: { allow: 0, warn: 0, block: 0 },
    malicious: { allow: 0, warn: 0, block: 0 },
  };

  Object.entries(matrix).forEach(([label, scenarios]) => {
    Object.entries(scenarios).forEach(([scenario, count]) => {
      const decision = inferDecisionFromScenario(scenario, label);
      if (normalized[label] && Object.hasOwn(normalized[label], decision)) {
        normalized[label][decision] += Number(count);
      }
    });
  });

  target.innerHTML = `
    <div class="matrix-table-wrap">
      <table class="matrix-table">
        <thead>
          <tr>
            <th>Класс</th>
            <th>allow</th>
            <th>warn</th>
            <th>block</th>
          </tr>
        </thead>
        <tbody>
          ${Object.entries(normalized)
            .map(
              ([label, decisions]) => `
                <tr>
                  <th>${escapeHtml(formatCategory(label, "label"))}</th>
                  <td>${decisions.allow}</td>
                  <td>${decisions.warn}</td>
                  <td>${decisions.block}</td>
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderConfusionMatrix(models) {
  const target = document.getElementById("confusion-matrix");
  if (!target) return;

  const leader = models.slice().sort((a, b) => Number(b.pr_auc_ovr) - Number(a.pr_auc_ovr))[0];
  if (!leader?.confusion_matrix) {
    target.innerHTML = '<div class="empty-state compact-empty">Матрица недоступна.</div>';
    return;
  }

  const labels = ["normal", "anomalous", "malicious"];
  target.innerHTML = `
    <div class="matrix-table-wrap">
      <table class="matrix-table">
        <thead>
          <tr>
            <th>${escapeHtml(leader.model)}</th>
            ${labels.map((label) => `<th>${escapeHtml(formatCategory(label, "label"))}</th>`).join("")}
          </tr>
        </thead>
        <tbody>
          ${leader.confusion_matrix
            .map(
              (row, rowIndex) => `
                <tr>
                  <th>${escapeHtml(formatCategory(labels[rowIndex], "label"))}</th>
                  ${row.map((value) => `<td>${value}</td>`).join("")}
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderJson(targetId, value) {
  const node = document.getElementById(targetId);
  if (!node) return;
  node.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function buildHighlightedPrompt(prompt, fragments, variant) {
  if (!prompt) return "";
  const matches = findHighlightMatches(prompt, fragments);
  const title = variant === "gliner" ? "Подсветка фрагментов GLiNER" : "Подсветка срабатываний правил";
  if (!matches.length) {
    return `
      <div class="highlight-card">
        <h3>${title}</h3>
        <p class="trigger-note">Система не смогла привязать срабатывание к точному буквальному фрагменту, поэтому ниже показан исходный запрос без подсветки.</p>
        <div class="highlight-preview">${escapeHtml(prompt)}</div>
      </div>
    `;
  }

  let cursor = 0;
  let html = "";
  matches.forEach((match) => {
    html += escapeHtml(prompt.slice(cursor, match.start));
    html += `<mark class="highlight-mark highlight-mark-${variant}">${escapeHtml(prompt.slice(match.start, match.end))}</mark>`;
    cursor = match.end;
  });
  html += escapeHtml(prompt.slice(cursor));

  return `
    <div class="highlight-card">
      <h3>${title}</h3>
      <div class="highlight-preview">${html}</div>
    </div>
  `;
}

function findHighlightMatches(prompt, fragments) {
  const normalizedPrompt = String(prompt || "");
  const lowerPrompt = normalizedPrompt.toLowerCase();
  const candidates = [...new Set((fragments || []).map((item) => String(item || "").trim()).filter((item) => item.length >= 2))]
    .sort((left, right) => right.length - left.length);

  const matches = [];
  candidates.forEach((fragment) => {
    const lowerFragment = fragment.toLowerCase();
    let startIndex = 0;
    while (startIndex < lowerPrompt.length) {
      const index = lowerPrompt.indexOf(lowerFragment, startIndex);
      if (index === -1) break;
      const end = index + lowerFragment.length;
      const overlaps = matches.some((match) => !(end <= match.start || index >= match.end));
      if (!overlaps) {
        matches.push({ start: index, end });
      }
      startIndex = index + 1;
    }
  });

  return matches.sort((left, right) => left.start - right.start);
}

function setButtonLoading(button, isLoading, label) {
  if (!button) return;
  button.disabled = isLoading;
  button.textContent = label;
}

function getApiBase() {
  const configured = window.MCP_FIREWALL_CONFIG?.apiBase?.trim();
  if (configured) {
    return configured.replace(/\/$/, "");
  }
  if (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost") {
    return LOCAL_API_BASE;
  }
  return LOCAL_API_BASE;
}

function formatDecision(value) {
  const map = {
    allow: "allow",
    warn: "warn",
    block: "block",
    skipped: "skipped",
    analyzed: "analyzed",
    unavailable: "unavailable",
    incomplete: "недостаточно данных",
    unknown: "сценарий не распознан",
    not_run: "не запускался",
    pending: "pending",
    error: "error",
  };
  return map[value] || value || "—";
}

function formatBool(value) {
  return value ? "ready" : "not ready";
}

function formatCategory(value, type) {
  if (type === "label") {
    return {
      normal: "normal",
      anomalous: "anomalous",
      malicious: "malicious",
    }[value] || value;
  }
  if (type === "decision") {
    return formatDecision(value);
  }
  if (type === "scenario") {
    return formatScenario(value);
  }
  if (type === "entity") {
    return String(value)
      .replaceAll("_", " ")
      .replace(/\b\w/g, (match) => match.toUpperCase());
  }
  if (type === "request_safety") {
    return {
      safe: "safe",
      suspicious: "suspicious",
    }[value] || value;
  }
  if (type === "source_type") {
    return String(value).replaceAll("mcp request", "MCP request").replaceAll("_", " ");
  }
  if (type === "template") {
    return String(value).replaceAll("_", " ");
  }
  return value;
}

function barToneClass(key, type) {
  if (type === "decision") {
    return {
      allow: "safe",
      warn: "warn",
      block: "danger",
    }[key] || "accent";
  }
  if (type === "label") {
    return {
      normal: "safe",
      anomalous: "warn",
      malicious: "danger",
    }[key] || "accent";
  }
  if (type === "request_safety") {
    return {
      safe: "safe",
      suspicious: "danger",
    }[key] || "accent";
  }
  return "accent";
}

function cleanFeatureName(feature) {
  return String(feature)
    .replace(/^feature_/, "")
    .replaceAll("_", " ");
}

function formatScenario(value) {
  return String(value)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function formatScenarioCompact(value) {
  const map = {
    benign_large_transfer: "Large transfer",
    benign_error_recovery: "Error recovery",
    benign_usage: "Benign usage",
    sensitive_file_access: "Sensitive file",
    public_endpoint_exfiltration: "Public endpoint",
    covert_safe_root_access: "Safe-root access",
    private_host_access: "Private host",
    noisy_borderline_search: "Borderline search",
    oversized_sensitive_query: "Oversized query",
    high_latency_search: "High-latency search",
    error_burst_like: "Error burst",
  };
  return map[value] || formatScenario(value);
}

function inferDecisionFromScenario(scenario, label) {
  if (label === "malicious") return "block";
  if (label === "anomalous") return "warn";
  return "allow";
}

function buildScenarioMatrixFallback(scenarioDistribution) {
  const matrix = {
    normal: {},
    anomalous: {},
    malicious: {},
  };

  Object.entries(scenarioDistribution || {}).forEach(([scenario, count]) => {
    if (scenario.startsWith("benign_")) {
      matrix.normal[scenario] = Number(count);
    } else if (
      ["error_burst_like", "high_latency_search", "noisy_borderline_search", "oversized_sensitive_query"].includes(scenario)
    ) {
      matrix.anomalous[scenario] = Number(count);
    } else {
      matrix.malicious[scenario] = Number(count);
    }
  });

  return matrix;
}

function formatDelta(before, after) {
  const delta = Number(after || 0) - Number(before || 0);
  return `${delta >= 0 ? "+" : ""}${delta.toFixed(4)}`;
}

function formatExampleRiskValue(row) {
  return Number(row?.risk_score || 0).toFixed(2);
}

function formatExampleRiskLabel(row) {
  return `risk ${Number(row?.risk_score || 0).toFixed(2)}`;
}

let globalTooltipNode = null;
let globalTooltipTarget = null;

function initGlobalTooltip() {
  if (globalTooltipNode) return;
  globalTooltipNode = document.createElement("div");
  globalTooltipNode.className = "ui-tooltip";
  globalTooltipNode.hidden = true;
  document.body.appendChild(globalTooltipNode);

  document.addEventListener("mouseover", (event) => {
    const target = event.target instanceof Element ? event.target.closest("[data-tooltip]") : null;
    if (!target) return;
    globalTooltipTarget = target;
    globalTooltipNode.innerHTML = escapeHtml(target.getAttribute("data-tooltip") || "").replaceAll("\n", "<br>");
    globalTooltipNode.hidden = false;
  });

  document.addEventListener("mousemove", (event) => {
    if (!globalTooltipNode || globalTooltipNode.hidden) return;
    positionTooltip(event.clientX, event.clientY);
  });

  document.addEventListener("mouseout", (event) => {
    if (!globalTooltipTarget) return;
    const nextTarget = event.relatedTarget instanceof Node ? event.relatedTarget : null;
    if (nextTarget && globalTooltipTarget.contains(nextTarget)) return;
    globalTooltipNode.hidden = true;
    globalTooltipTarget = null;
  });

  document.addEventListener("scroll", () => {
    if (globalTooltipNode) globalTooltipNode.hidden = true;
  });
}

function positionTooltip(clientX, clientY) {
  if (!globalTooltipNode) return;
  const gap = 14;
  const maxLeft = window.innerWidth - globalTooltipNode.offsetWidth - 12;
  const maxTop = window.innerHeight - globalTooltipNode.offsetHeight - 12;
  const left = Math.min(clientX + gap, maxLeft);
  const top = Math.min(clientY + gap, maxTop);
  globalTooltipNode.style.left = `${Math.max(12, left)}px`;
  globalTooltipNode.style.top = `${Math.max(12, top)}px`;
}

function tooltipAttr(text) {
  return `data-tooltip="${escapeHtml(text)}"`;
}

function formatParamValue(value) {
  if (typeof value !== "number") return String(value ?? "—");
  if (Number.isInteger(value)) return String(value);
  return value.toFixed(4);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
