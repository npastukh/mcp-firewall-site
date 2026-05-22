const STORAGE_KEY = "mcp_firewall_api_base";
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
  const page = document.body.dataset.page;
  if (page === "demo") {
    initDemoPage();
  }
  if (page === "dashboard") {
    initDashboardPage();
  }
});

function initDemoPage() {
  const apiInput = document.getElementById("api-base-input");
  const healthButton = document.getElementById("api-health-button");
  const runButton = document.getElementById("run-analysis-button");
  const randomButton = document.getElementById("random-request-button");
  const promptInput = document.getElementById("prompt-input");
  const transportInput = document.getElementById("transport-input");

  apiInput.value = localStorage.getItem(STORAGE_KEY) || getDefaultApiBase();
  renderExamples();

  healthButton.addEventListener("click", () => checkApiHealth());
  runButton.addEventListener("click", () =>
    runAnalysis({
      prompt: promptInput.value.trim(),
      transportType: transportInput.value,
    })
  );
  randomButton.addEventListener("click", () => applyRandomExample());
  apiInput.addEventListener("change", () => storeApiBase(apiInput.value));

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
  const stateNode = document.getElementById("api-health-state");
  const noteNode = document.getElementById("api-health-note");
  const button = document.getElementById("api-health-button");

  setButtonLoading(button, true, "Проверяем...");
  stateNode.textContent = "проверка...";
  noteNode.textContent = `Пытаемся подключиться к ${apiBase}`;

  try {
    const response = await fetch(`${apiBase}/api/health`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    stateNode.textContent = "соединение установлено";
    noteNode.textContent =
      `CatBoost runtime: ${formatBool(data.catboost_runtime_ready)}. GLiNER checkpoint: ${formatBool(data.gliner_checkpoint_ready)}.`;
  } catch (error) {
    stateNode.textContent = "соединение не установлено";
    noteNode.textContent = `Не удалось обратиться к API: ${error.message}`;
  } finally {
    setButtonLoading(button, false, "Проверить API");
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
    responseStatus.textContent = "ответ получен";

    renderOverallResult(data);
    renderRulesStage(data.rules_catboost);
    renderGlinerStage(data.gliner_lora);
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
  target.innerHTML = `
    <article class="decision-card ${tone}">
      <div class="decision-head">
        <span class="decision-label">Final decision</span>
        <strong>${formatDecision(decision)}</strong>
      </div>
      <p class="decision-rationale">${escapeHtml(data.final_rationale || "Результат ещё не сформирован.")}</p>
      <div class="decision-meta">
        <span>Stage 1: ${formatDecision(data.rules_catboost?.decision || "pending")}</span>
        <span>Stage 2: ${formatDecision(data.gliner_lora?.decision || data.gliner_lora?.status || "pending")}</span>
      </div>
    </article>
  `;
}

function renderRulesStage(stage) {
  const target = document.getElementById("rules-stage");
  if (!stage) {
    target.innerHTML = '<div class="empty-state">Результат первого этапа отсутствует.</div>';
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
    </article>
  `;
}

function renderGlinerStage(stage) {
  const target = document.getElementById("gliner-stage");
  if (!stage) {
    target.innerHTML = '<div class="empty-state">Результат второго этапа отсутствует.</div>';
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
    </article>
  `;
}

async function initDashboardPage() {
  try {
    const response = await fetch("../data/dashboard.json");
    const data = await response.json();

    document.getElementById("dashboard-scheme").textContent =
      data.evaluation?.summary?.current_scheme || data.meta?.current_scheme || "Rules + CatBoost";

    renderKpis(data);
    renderArchitecture(data);
    renderBarList("label-chart", data.summary?.label_counts || {}, "label");
    renderBarList("decision-chart", data.summary?.decision_counts || {}, "decision");
    renderBarList("tool-chart", data.summary?.tool_counts || {}, "tool");
    renderBarList("scenario-chart", data.summary?.scenario_counts || {}, "scenario");
    renderDecisionMatrix(data.summary?.scenario_matrix || {});
    renderLeaderboard(data.evaluation?.model_metrics || []);
    renderFeatureImportance(data.evaluation?.feature_importance || []);
    renderConfusionMatrix(data.evaluation?.model_metrics || []);
    renderModelTable(data.evaluation?.model_metrics || []);
  } catch (error) {
    const target = document.getElementById("kpi-grid");
    if (target) {
      target.innerHTML = `<article class="kpi-card"><strong>Не удалось загрузить dashboard.json</strong><p>${escapeHtml(
        error.message
      )}</p></article>`;
    }
  }
}

function renderArchitecture(data) {
  const target = document.getElementById("architecture-grid");
  if (!target) return;

  const scheme = data.evaluation?.summary?.current_scheme || "Rules + CatBoost";
  const cards = [
    {
      step: "01",
      title: "Агентный запрос",
      text: "Пользовательский текст сначала интерпретируется в структурированный MCP tools/call.",
    },
    {
      step: "02",
      title: "Rules + CatBoost",
      text: `Базовый контур ${scheme} проверяет правила, признаки и риск-оценку для каждого события.`,
    },
    {
      step: "03",
      title: "GLiNER + LoRA",
      text: "Полнотекстовый semantic-stage подключается только к подозрительным кейсам, а не ко всем запросам подряд.",
    },
    {
      step: "04",
      title: "Final decision",
      text: "Система возвращает общий verdict и объяснение, какой контур повлиял на итоговое решение.",
    },
  ];

  target.innerHTML = cards
    .map(
      (card) => `
        <article class="pipeline-card">
          <span class="pipeline-step">${escapeHtml(card.step)}</span>
          <h3>${escapeHtml(card.title)}</h3>
          <p>${escapeHtml(card.text)}</p>
        </article>
      `
    )
    .join("");
}

function renderKpis(data) {
  const grid = document.getElementById("kpi-grid");
  const totalRecords = data.meta?.total_records || 0;
  const currentScheme = data.evaluation?.summary?.current_scheme || "Rules + CatBoost";
  const bestPrAuc = data.evaluation?.summary?.best_pr_auc_ovr?.value || 0;
  const bestBalancedAccuracy = data.evaluation?.summary?.best_balanced_accuracy?.value || 0;

  const cards = [
    {
      label: "Всего событий",
      value: String(totalRecords),
      note: "Объём синтетического лабораторного датасета.",
    },
    {
      label: "Текущая схема",
      value: currentScheme,
      note: "Рабочий контур, используемый как основа live-демо.",
    },
    {
      label: "Лучший PR-AUC OVR",
      value: Number(bestPrAuc).toFixed(4),
      note: "Основная метрика качества на редких опасных сценариях.",
    },
    {
      label: "Balanced Accuracy",
      value: Number(bestBalancedAccuracy).toFixed(4),
      note: "Показывает, насколько модель стабильно различает все классы событий.",
    },
  ];

  grid.innerHTML = cards
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
        <div class="bar-item">
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
        <div class="bar-item">
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
        <div class="bar-item">
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

function renderModelTable(models) {
  const target = document.getElementById("model-table");
  const sorted = models.slice().sort((a, b) => Number(b.pr_auc_ovr) - Number(a.pr_auc_ovr));
  target.innerHTML = sorted
    .map(
      (model) => `
        <tr>
          <td>${escapeHtml(model.model)}</td>
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

function setButtonLoading(button, isLoading, label) {
  if (!button) return;
  button.disabled = isLoading;
  button.textContent = label;
}

function getApiBase() {
  const input = document.getElementById("api-base-input");
  const value = (input?.value || localStorage.getItem(STORAGE_KEY) || getDefaultApiBase()).trim().replace(/\/$/, "");
  storeApiBase(value);
  return value;
}

function storeApiBase(value) {
  const normalized = value.trim().replace(/\/$/, "");
  localStorage.setItem(STORAGE_KEY, normalized);
}

function getDefaultApiBase() {
  const configured = window.MCP_FIREWALL_CONFIG?.apiBase?.trim();
  if (configured) {
    return configured.replace(/\/$/, "");
  }
  if (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost") {
    return LOCAL_API_BASE;
  }
  return "";
}

function formatDecision(value) {
  const map = {
    allow: "allow",
    warn: "warn",
    block: "block",
    skipped: "skipped",
    analyzed: "analyzed",
    unavailable: "unavailable",
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

function inferDecisionFromScenario(scenario, label) {
  if (label === "malicious") return "block";
  if (label === "anomalous") return "warn";
  return "allow";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
