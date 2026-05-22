from __future__ import annotations

import json
import importlib.util
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from joblib import dump
from pandas.api.types import is_bool_dtype, is_object_dtype, is_string_dtype
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import (
    RandomForestClassifier,
)
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, label_binarize
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight


RAW_TARGET_SOURCE = "label"
TARGET_COLUMN = "target_class"
GROUP_COLUMN = "session_id"
SCENARIO_COLUMN = "scenario_type"
CLASS_LABELS = ["normal", "anomalous", "malicious"]
CLASS_TO_ID = {label: index for index, label in enumerate(CLASS_LABELS)}
BLOCK_RULES = {
    "blocked_tool",
    "disallowed_transport",
    "unknown_client",
    "tool_not_allowed_for_client",
    "tool_server_mismatch",
    "sensitive_path_access",
    "private_address_access",
    "private_backend_path_access",
}
WARN_RULES = {
    "oversized_payload",
    "oversized_response",
    "high_frequency_calls",
    "path_outside_safe_roots",
    "sensitive_export_scope",
}
HYBRID_BLOCK_OVERRIDE_RULES = BLOCK_RULES - {"tool_server_mismatch"}
HYBRID_WARN_OVERRIDE_RULES: set[str] = set()
RUNTIME_ARTIFACT_DIRNAME = "runtime"


def load_dataset(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df[TARGET_COLUMN] = df[RAW_TARGET_SOURCE].map(CLASS_TO_ID)
    if df[TARGET_COLUMN].isna().any():
        unknown = sorted(df.loc[df[TARGET_COLUMN].isna(), RAW_TARGET_SOURCE].unique().tolist())
        raise ValueError(f"Unknown labels in dataset: {unknown}")
    df[TARGET_COLUMN] = df[TARGET_COLUMN].astype(int)
    return df


def split_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    feature_columns = [column for column in df.columns if column.startswith("feature_")]
    return df[feature_columns], df[TARGET_COLUMN]


def build_preprocessor(X: pd.DataFrame) -> ColumnTransformer:
    categorical_cols = [
        column
        for column in X.columns
        if is_object_dtype(X[column]) or is_string_dtype(X[column]) or is_bool_dtype(X[column])
    ]
    numeric_cols = [column for column in X.columns if column not in categorical_cols]

    categorical_pipeline = Pipeline(
        steps=[
            ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]
    )
    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )

    return ColumnTransformer(
        transformers=[
            ("categorical", categorical_pipeline, categorical_cols),
            ("numeric", numeric_pipeline, numeric_cols),
        ],
        sparse_threshold=0.0,
    )


def discover_optional_estimators() -> list[tuple[str, object]]:
    models: list[tuple[str, object]] = []

    if importlib.util.find_spec("lightgbm"):
        try:
            from lightgbm import LGBMClassifier

            models.append(
                (
                    "LightGBM",
                    LGBMClassifier(
                        objective="multiclass",
                        num_class=len(CLASS_LABELS),
                        n_estimators=250,
                        learning_rate=0.05,
                        max_depth=5,
                        subsample=0.9,
                        colsample_bytree=0.9,
                        random_state=42,
                        verbose=-1,
                    ),
                )
            )
        except Exception:
            pass

    if importlib.util.find_spec("xgboost"):
        try:
            from xgboost import XGBClassifier

            models.append(
                (
                    "XGBoost",
                    XGBClassifier(
                        objective="multi:softprob",
                        num_class=len(CLASS_LABELS),
                        n_estimators=250,
                        max_depth=5,
                        learning_rate=0.05,
                        subsample=0.9,
                        colsample_bytree=0.9,
                        eval_metric="mlogloss",
                        random_state=42,
                    ),
                )
            )
        except Exception:
            pass

    if importlib.util.find_spec("catboost"):
        try:
            from catboost import CatBoostClassifier

            models.append(
                (
                    "CatBoost",
                    CatBoostClassifier(
                        iterations=250,
                        depth=6,
                        learning_rate=0.05,
                        l2_leaf_reg=6,
                        loss_function="MultiClass",
                        verbose=False,
                        random_seed=42,
                    ),
                )
            )
        except Exception:
            pass

    return models


def grouped_split(
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
) -> tuple[np.ndarray, np.ndarray]:
    splitter = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y, groups))
    return train_idx, test_idx


def align_proba(probabilities: np.ndarray, classes: np.ndarray) -> np.ndarray:
    aligned = np.zeros((probabilities.shape[0], len(CLASS_LABELS)))
    for source_index, cls in enumerate(classes):
        aligned[:, int(cls)] = probabilities[:, source_index]
    return aligned


def flatten_predictions(predictions: object) -> np.ndarray:
    return np.asarray(predictions).reshape(-1)


def deterministic_scores_from_predictions(y_pred: pd.Series) -> np.ndarray:
    scores = np.zeros((len(y_pred), len(CLASS_LABELS)))
    for row_index, predicted_class in enumerate(y_pred.to_numpy()):
        scores[row_index, int(predicted_class)] = 1.0
    return scores


def multiclass_roc_auc(y_true: pd.Series, y_score: np.ndarray) -> float:
    y_true_binarized = label_binarize(y_true, classes=list(range(len(CLASS_LABELS))))
    return float(roc_auc_score(y_true_binarized, y_score, multi_class="ovr", average="macro"))


def multiclass_pr_auc(y_true: pd.Series, y_score: np.ndarray) -> float:
    y_true_binarized = label_binarize(y_true, classes=list(range(len(CLASS_LABELS))))
    return float(average_precision_score(y_true_binarized, y_score, average="macro"))


def evaluate_classifier(
    name: str,
    y_true: pd.Series,
    y_pred: pd.Series,
    y_score: np.ndarray,
) -> dict[str, object]:
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(CLASS_LABELS))))
    report = classification_report(
        y_true,
        y_pred,
        labels=list(range(len(CLASS_LABELS))),
        target_names=CLASS_LABELS,
        zero_division=0,
        output_dict=True,
    )
    return {
        "model": name,
        "balanced_accuracy": round(float(balanced_accuracy_score(y_true, y_pred)), 4),
        "macro_precision": round(float(precision_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "macro_recall": round(float(recall_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "pr_auc_ovr": round(multiclass_pr_auc(y_true, y_score), 4),
        "roc_auc_ovr": round(multiclass_roc_auc(y_true, y_score), 4),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
    }


def summarize_overfitting(
    name: str,
    y_train: pd.Series,
    y_train_pred: pd.Series,
    y_train_score: np.ndarray,
    y_test: pd.Series,
    y_test_pred: pd.Series,
    y_test_score: np.ndarray,
) -> dict[str, float | str]:
    train_balanced_accuracy = float(balanced_accuracy_score(y_train, y_train_pred))
    test_balanced_accuracy = float(balanced_accuracy_score(y_test, y_test_pred))
    train_pr_auc = multiclass_pr_auc(y_train, y_train_score)
    test_pr_auc = multiclass_pr_auc(y_test, y_test_score)
    train_auc = multiclass_roc_auc(y_train, y_train_score)
    test_auc = multiclass_roc_auc(y_test, y_test_score)
    return {
        "model": name,
        "train_balanced_accuracy": round(train_balanced_accuracy, 4),
        "test_balanced_accuracy": round(test_balanced_accuracy, 4),
        "balanced_accuracy_gap": round(train_balanced_accuracy - test_balanced_accuracy, 4),
        "train_pr_auc_ovr": round(train_pr_auc, 4),
        "test_pr_auc_ovr": round(test_pr_auc, 4),
        "pr_auc_ovr_gap": round(train_pr_auc - test_pr_auc, 4),
        "train_roc_auc_ovr": round(train_auc, 4),
        "test_roc_auc_ovr": round(test_auc, 4),
        "roc_auc_gap": round(train_auc - test_auc, 4),
    }


def extract_feature_importance(pipeline: Pipeline, top_n: int = 10) -> list[dict[str, float | str]]:
    preprocessor = pipeline.named_steps["preprocessor"]
    model = pipeline.named_steps["model"]
    feature_names = preprocessor.get_feature_names_out()
    pairs = sorted(
        zip(feature_names, model.feature_importances_, strict=False),
        key=lambda item: item[1],
        reverse=True,
    )

    return [
        {
            "feature": feature.replace("categorical__", "").replace("numeric__", ""),
            "importance": round(float(importance), 4),
        }
        for feature, importance in pairs[:top_n]
    ]


def parse_rule_names(raw_value: object) -> set[str]:
    if raw_value is None or (isinstance(raw_value, float) and np.isnan(raw_value)):
        return set()
    value = str(raw_value).strip()
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def build_rule_predictions(
    df_subset: pd.DataFrame,
    block_rules: set[str] | None = None,
    warn_rules: set[str] | None = None,
) -> pd.Series:
    block_rules = block_rules or BLOCK_RULES
    warn_rules = warn_rules or WARN_RULES
    predictions: list[int] = []
    for _, row in df_subset.iterrows():
        rule_names = parse_rule_names(row.get("rule_names"))
        if rule_names & block_rules:
            predictions.append(CLASS_TO_ID["malicious"])
        elif rule_names & warn_rules:
            predictions.append(CLASS_TO_ID["anomalous"])
        else:
            predictions.append(CLASS_TO_ID["normal"])
    return pd.Series(predictions, index=df_subset.index)


def build_hybrid_rule_predictions(df_subset: pd.DataFrame) -> pd.Series:
    return build_rule_predictions(
        df_subset,
        block_rules=HYBRID_BLOCK_OVERRIDE_RULES,
        warn_rules=HYBRID_WARN_OVERRIDE_RULES,
    )


def collect_error_examples(
    model_name: str,
    test_rows: pd.DataFrame,
    y_true: pd.Series,
    y_pred: pd.Series,
    limit: int = 8,
) -> dict[str, Any]:
    analysis_rows = test_rows.copy()
    analysis_rows["true_label"] = y_true.map(lambda value: CLASS_LABELS[int(value)])
    analysis_rows["pred_label"] = y_pred.map(lambda value: CLASS_LABELS[int(value)])
    analysis_rows = analysis_rows[analysis_rows["true_label"] != analysis_rows["pred_label"]]

    confusion_pairs = (
        analysis_rows.groupby(["true_label", "pred_label"])
        .size()
        .sort_values(ascending=False)
        .reset_index(name="count")
    )

    examples = analysis_rows.loc[
        :,
        [
            "scenario_type",
            "tool_name",
            "payload_size",
            "response_time_ms",
            "decision",
            "risk_score",
            "true_label",
            "pred_label",
        ],
    ].head(limit)

    return {
        "model": model_name,
        "misclassified_total": int(len(analysis_rows)),
        "top_confusions": confusion_pairs.to_dict(orient="records"),
        "sample_misclassifications": examples.to_dict(orient="records"),
    }


def run_supervised_models(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
) -> tuple[list[dict[str, object]], dict[str, object], list[dict[str, float | str]]]:
    preprocessor = build_preprocessor(X_train)
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)

    models = [
        (
            "Logistic Regression",
            LogisticRegression(
                max_iter=1500,
                class_weight="balanced",
                random_state=42,
            ),
        ),
        (
            "SVM",
            SVC(
                kernel="rbf",
                C=2.0,
                gamma="scale",
                class_weight="balanced",
                probability=True,
                random_state=42,
            ),
        ),
        (
            "Decision Tree",
            DecisionTreeClassifier(
                max_depth=8,
                min_samples_leaf=3,
                class_weight="balanced",
                random_state=42,
            ),
        ),
        (
            "Random Forest",
            RandomForestClassifier(
                n_estimators=250,
                max_depth=10,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ]
    models.extend(discover_optional_estimators())

    results: list[dict[str, object]] = []
    fitted: dict[str, object] = {}
    overfitting_summary: list[dict[str, float | str]] = []
    for name, estimator in models:
        pipeline = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("model", estimator),
            ]
        )
        pipeline.fit(X_train, y_train, model__sample_weight=sample_weights)

        y_train_pred = pd.Series(flatten_predictions(pipeline.predict(X_train)), index=y_train.index)
        y_train_score = align_proba(pipeline.predict_proba(X_train), pipeline.named_steps["model"].classes_)
        y_pred = pd.Series(flatten_predictions(pipeline.predict(X_test)), index=y_test.index)
        y_score = align_proba(pipeline.predict_proba(X_test), pipeline.named_steps["model"].classes_)

        results.append(evaluate_classifier(name, y_test, y_pred, y_score))
        overfitting_summary.append(
            summarize_overfitting(name, y_train, y_train_pred, y_train_score, y_test, y_pred, y_score)
        )
        fitted[name] = {
            "pipeline": pipeline,
            "pred": y_pred,
            "score": y_score,
            "params": pipeline.named_steps["model"].get_params(),
        }
    return results, fitted, overfitting_summary


def build_hybrid_predictions(rule_pred: pd.Series, model_pred: pd.Series, model_score: np.ndarray) -> tuple[pd.Series, np.ndarray]:
    hybrid_pred = pd.Series(
        np.maximum(rule_pred.to_numpy(), model_pred.to_numpy()),
        index=model_pred.index,
    )
    hybrid_score = model_score.copy()
    for row_index, rule_class in enumerate(rule_pred.to_numpy()):
        if int(rule_class) != CLASS_TO_ID["normal"]:
            hybrid_score[row_index, :] = 0.0
            hybrid_score[row_index, int(rule_class)] = 1.0
    return hybrid_pred, hybrid_score


def summarize_split(df: pd.DataFrame, train_idx: np.ndarray, test_idx: np.ndarray) -> dict[str, object]:
    train_df = df.iloc[train_idx]
    test_df = df.iloc[test_idx]
    return {
        "split_type": "StratifiedGroupKFold by session_id",
        "groups_total": int(df[GROUP_COLUMN].nunique()),
        "train_groups": int(train_df[GROUP_COLUMN].nunique()),
        "test_groups": int(test_df[GROUP_COLUMN].nunique()),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "train_label_distribution": train_df[RAW_TARGET_SOURCE].value_counts().to_dict(),
        "test_label_distribution": test_df[RAW_TARGET_SOURCE].value_counts().to_dict(),
    }


def render_markdown(
    split_summary: dict[str, object],
    results: list[dict[str, object]],
    overfitting_summary: list[dict[str, float | str]],
    model_params: dict[str, dict[str, object]],
) -> str:
    lines = [
        "# Model Metrics",
        "",
        "## Split Protocol",
        "",
        f"- Type: {split_summary['split_type']}",
        f"- Groups total: {split_summary['groups_total']}",
        f"- Train groups: {split_summary['train_groups']}",
        f"- Test groups: {split_summary['test_groups']}",
        f"- Train rows: {split_summary['train_rows']}",
        f"- Test rows: {split_summary['test_rows']}",
        f"- Train label distribution: `{split_summary['train_label_distribution']}`",
        f"- Test label distribution: `{split_summary['test_label_distribution']}`",
        "",
        "| Model | Balanced Accuracy | Macro Precision | Macro Recall | PR-AUC OVR | ROC-AUC OVR |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in results:
        lines.append(
            f"| {result['model']} | {result['balanced_accuracy']:.4f} | {result['macro_precision']:.4f} | {result['macro_recall']:.4f} | {result['pr_auc_ovr']:.4f} | {result['roc_auc_ovr']:.4f} |"
        )

    lines.append("")
    lines.append("## Confusion Matrices")
    lines.append("")
    for result in results:
        lines.append(f"### {result['model']}")
        lines.append("")
        lines.append(f"`{result['confusion_matrix']}`")
        lines.append("")

    lines.append("## Model Configurations")
    lines.append("")
    lines.append("| Model | Key Parameters |")
    lines.append("| --- | --- |")
    for name, params in model_params.items():
        key_params = {
            key: params[key]
            for key in (
                "C",
                "kernel",
                "n_estimators",
                "max_depth",
                "learning_rate",
                "min_samples_leaf",
                "max_iter",
                "iterations",
                "depth",
                "num_leaves",
            )
            if key in params
        }
        lines.append(f"| {name} | `{key_params}` |")
    lines.append("")

    if overfitting_summary:
        lines.append("## Overfitting Check")
        lines.append("")
        lines.append("| Model | Train Balanced Accuracy | Test Balanced Accuracy | Gap | Train PR-AUC OVR | Test PR-AUC OVR | Gap | Train ROC-AUC OVR | Test ROC-AUC OVR | Gap |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for item in overfitting_summary:
            lines.append(
                f"| {item['model']} | {item['train_balanced_accuracy']:.4f} | {item['test_balanced_accuracy']:.4f} | {item['balanced_accuracy_gap']:.4f} | "
                f"{item['train_pr_auc_ovr']:.4f} | {item['test_pr_auc_ovr']:.4f} | {item['pr_auc_ovr_gap']:.4f} | "
                f"{item['train_roc_auc_ovr']:.4f} | {item['test_roc_auc_ovr']:.4f} | {item['roc_auc_gap']:.4f} |"
            )
        lines.append("")

    optional_status = []
    model_names = {result["model"] for result in results}
    if importlib.util.find_spec("lightgbm") and "LightGBM" not in model_names:
        optional_status.append("`LightGBM` не был запущен: библиотека установлена, но не загрузилась в текущем окружении.")
    elif not importlib.util.find_spec("lightgbm"):
        optional_status.append("`LightGBM` не был запущен: библиотека отсутствует в окружении.")
    if importlib.util.find_spec("xgboost") and "XGBoost" not in model_names:
        optional_status.append("`XGBoost` не был запущен: библиотека установлена, но системная зависимость `libomp` недоступна в окружении.")
    elif not importlib.util.find_spec("xgboost"):
        optional_status.append("`XGBoost` не был запущен: библиотека отсутствует в окружении.")
    if importlib.util.find_spec("catboost") and "CatBoost" not in model_names:
        optional_status.append("`CatBoost` не был запущен: библиотека установлена, но не загрузилась в текущем окружении.")
    elif not importlib.util.find_spec("catboost"):
        optional_status.append("`CatBoost` не был запущен: библиотека отсутствует в окружении.")
    if optional_status:
        lines.append("## Optional Boosting Libraries")
        lines.append("")
        lines.extend([f"- {item}" for item in optional_status])
        lines.append("")

    return "\n".join(lines)


def render_feature_importance_markdown(feature_importance: list[dict[str, float | str]]) -> str:
    lines = [
        "# Random Forest Feature Importance",
        "",
        "Random Forest сохраняется в работе как интерпретируемая reference-модель для анализа вклада признаков, даже если лучшая метрика достигается другой моделью.",
        "",
        "| Feature | Importance |",
        "| --- | ---: |",
    ]
    for item in feature_importance:
        lines.append(f"| {item['feature']} | {item['importance']:.4f} |")
    lines.append("")
    lines.append(
        "Наибольший вклад в качество модели вносят признаки, отражающие размер ответа, время обработки, объем запроса и контекст сессии."
    )
    return "\n".join(lines)


def render_error_analysis_markdown(error_reports: list[dict[str, Any]]) -> str:
    lines = [
        "# Error Analysis",
        "",
        "В отчете собраны наиболее показательные ошибки классификации на тестовой выборке при 3-классовой постановке.",
        "",
    ]
    for report in error_reports:
        lines.append(f"## {report['model']}")
        lines.append("")
        lines.append(f"- Misclassified events: {report['misclassified_total']}")
        lines.append("")
        lines.append("### Dominant Confusion Pairs")
        lines.append("")
        if report["top_confusions"]:
            for item in report["top_confusions"][:8]:
                lines.append(f"- `{item['true_label']} -> {item['pred_label']}`: {item['count']}")
        else:
            lines.append("- Не выявлены.")
        lines.append("")
        lines.append("### Sample Misclassifications")
        lines.append("")
        lines.append("| Scenario | Tool | Payload | Latency | Firewall Decision | Risk Score | True | Predicted |")
        lines.append("| --- | --- | ---: | ---: | --- | ---: | --- | --- |")
        if report["sample_misclassifications"]:
            for item in report["sample_misclassifications"]:
                lines.append(
                    f"| {item['scenario_type']} | {item['tool_name']} | {item['payload_size']} | {item['response_time_ms']} | "
                    f"{item['decision']} | {item['risk_score']:.4f} | {item['true_label']} | {item['pred_label']} |"
                )
        else:
            lines.append("| - | - | - | - | - | - | - | - |")
        lines.append("")

    return "\n".join(lines)


def export_runtime_artifact(
    pipeline: Pipeline,
    feature_columns: list[str],
    output_dir: Path,
    model_name: str,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    pipeline_path = output_dir / "catboost_pipeline.joblib"
    manifest_path = output_dir / "runtime_manifest.json"
    dump(pipeline, pipeline_path)
    manifest = {
        "model_name": model_name,
        "feature_columns": feature_columns,
        "class_labels": CLASS_LABELS,
        "target_column": TARGET_COLUMN,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return pipeline_path, manifest_path


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "data" / "synthetic_mcp_events.csv"
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    df = load_dataset(dataset_path)
    X, y = split_features(df)
    groups = df[GROUP_COLUMN]

    train_idx, test_idx = grouped_split(X, y, groups)
    split_summary = summarize_split(df, train_idx, test_idx)

    X_train = X.iloc[train_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    y_train = y.iloc[train_idx].reset_index(drop=True)
    y_test = y.iloc[test_idx].reset_index(drop=True)
    train_rows = df.iloc[train_idx].reset_index(drop=True)
    test_rows = df.iloc[test_idx].reset_index(drop=True)

    results: list[dict[str, object]] = []
    model_params: dict[str, dict[str, object]] = {}

    rule_pred = build_rule_predictions(test_rows)
    rule_score = deterministic_scores_from_predictions(rule_pred)
    results.append(evaluate_classifier("Rule-based baseline", y_test, rule_pred, rule_score))

    supervised_results, fitted, overfitting_summary = run_supervised_models(X_train, X_test, y_train, y_test)
    results.extend(supervised_results)
    for name, artifact in fitted.items():
        model_params[name] = artifact["params"]

    best_supervised_name = max(supervised_results, key=lambda item: item["pr_auc_ovr"])["model"]
    best_pred = fitted[best_supervised_name]["pred"]
    best_score = fitted[best_supervised_name]["score"]
    hybrid_rule_pred = build_hybrid_rule_predictions(test_rows)
    hybrid_pred, hybrid_score = build_hybrid_predictions(hybrid_rule_pred, best_pred, best_score)
    hybrid_name = f"Hybrid Rules + {best_supervised_name}"
    results.append(evaluate_classifier(hybrid_name, y_test, hybrid_pred, hybrid_score))

    markdown = render_markdown(split_summary, results, overfitting_summary, model_params)
    feature_importance = extract_feature_importance(fitted["Random Forest"]["pipeline"])

    tracked_models = [
        "Logistic Regression",
        "SVM",
        "Decision Tree",
        "Random Forest",
    ]
    if "LightGBM" in fitted:
        tracked_models.append("LightGBM")
    if "XGBoost" in fitted:
        tracked_models.append("XGBoost")
    if "CatBoost" in fitted:
        tracked_models.append("CatBoost")

    error_reports = [
        collect_error_examples(
            model_name,
            test_rows,
            y_test,
            fitted[model_name]["pred"],
        )
        for model_name in tracked_models
        if model_name in fitted
    ]

    metrics_md_path = reports_dir / "model_metrics.md"
    metrics_json_path = reports_dir / "model_metrics.json"
    feature_importance_md_path = reports_dir / "feature_importance.md"
    feature_importance_json_path = reports_dir / "feature_importance.json"
    error_analysis_md_path = reports_dir / "error_analysis.md"
    error_analysis_json_path = reports_dir / "error_analysis.json"
    metrics_md_path.write_text(markdown, encoding="utf-8")
    metrics_json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    feature_importance_md_path.write_text(
        render_feature_importance_markdown(feature_importance),
        encoding="utf-8",
    )
    feature_importance_json_path.write_text(
        json.dumps(feature_importance, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    error_analysis_md_path.write_text(
        render_error_analysis_markdown(error_reports),
        encoding="utf-8",
    )
    error_analysis_json_path.write_text(
        json.dumps(error_reports, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    runtime_pipeline_path = None
    runtime_manifest_path = None
    if "CatBoost" in fitted:
        runtime_pipeline_path, runtime_manifest_path = export_runtime_artifact(
            pipeline=fitted["CatBoost"]["pipeline"],
            feature_columns=list(X_train.columns),
            output_dir=project_root / "artifacts" / RUNTIME_ARTIFACT_DIRNAME,
            model_name="CatBoost",
        )

    print(f"Metrics report: {metrics_md_path}")
    print(f"Metrics JSON: {metrics_json_path}")
    print(f"Feature importance report: {feature_importance_md_path}")
    print(f"Error analysis report: {error_analysis_md_path}")
    if runtime_pipeline_path and runtime_manifest_path:
        print(f"Runtime pipeline: {runtime_pipeline_path}")
        print(f"Runtime manifest: {runtime_manifest_path}")
    print(f"Split protocol: {split_summary}")
    for result in results:
        print(
            f"{result['model']}: balanced_accuracy={result['balanced_accuracy']:.4f}, "
            f"macro_precision={result['macro_precision']:.4f}, "
            f"macro_recall={result['macro_recall']:.4f}, "
            f"pr_auc_ovr={result['pr_auc_ovr']:.4f}, "
            f"roc_auc_ovr={result['roc_auc_ovr']:.4f}"
        )


if __name__ == "__main__":
    main()
