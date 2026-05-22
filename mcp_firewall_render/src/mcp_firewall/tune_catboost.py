from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from catboost import CatBoostClassifier
from scipy.stats import randint, uniform
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV, StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.utils.class_weight import compute_sample_weight

from mcp_firewall.train_models import (
    build_hybrid_predictions,
    build_hybrid_rule_predictions,
    build_preprocessor,
    build_rule_predictions,
    evaluate_classifier,
    load_dataset,
    split_features,
    summarize_split,
    deterministic_scores_from_predictions,
    grouped_split,
    multiclass_pr_auc,
    align_proba,
    flatten_predictions,
    CLASS_LABELS,
    GROUP_COLUMN,
)
def build_estimator(params: dict[str, float | int]) -> CatBoostClassifier:
    return CatBoostClassifier(
        iterations=int(params["iterations"]),
        depth=int(params["depth"]),
        learning_rate=float(params["learning_rate"]),
        l2_leaf_reg=float(params["l2_leaf_reg"]),
        random_strength=float(params.get("random_strength", 1.0)),
        bagging_temperature=float(params.get("bagging_temperature", 0.0)),
        loss_function="MultiClass",
        verbose=False,
        random_seed=42,
        allow_writing_files=False,
    )


def pr_auc_scorer(estimator: Pipeline, X_fold: pd.DataFrame, y_fold: pd.Series) -> float:
    model = estimator.named_steps["model"]
    y_score = align_proba(estimator.predict_proba(X_fold), model.classes_)
    return multiclass_pr_auc(y_fold, y_score)


def run_cv_search(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    train_groups: pd.Series,
) -> tuple[dict[str, float | int], list[dict[str, float | int]]]:
    preprocessor = build_preprocessor(X_train)
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    baseline_params = {"iterations": 250, "depth": 6, "learning_rate": 0.05, "l2_leaf_reg": 3}
    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", build_estimator(baseline_params)),
        ]
    )
    param_grid = {
        "model__iterations": [250, 350, 500],
        "model__depth": [4, 6, 8],
        "model__learning_rate": [0.03, 0.05],
        "model__l2_leaf_reg": [3, 6],
    }
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
    search = GridSearchCV(
        estimator=pipeline,
        param_grid=param_grid,
        scoring=pr_auc_scorer,
        cv=splitter,
        refit=True,
        n_jobs=1,
        verbose=0,
        return_train_score=False,
    )
    search.fit(X_train, y_train, groups=train_groups, model__sample_weight=sample_weights)

    best_params = {
        "iterations": int(search.best_params_["model__iterations"]),
        "depth": int(search.best_params_["model__depth"]),
        "learning_rate": float(search.best_params_["model__learning_rate"]),
        "l2_leaf_reg": float(search.best_params_["model__l2_leaf_reg"]),
    }

    results: list[dict[str, float | int]] = []
    for index in range(len(search.cv_results_["params"])):
        item = {
            "iterations": int(search.cv_results_["param_model__iterations"][index]),
            "depth": int(search.cv_results_["param_model__depth"][index]),
            "learning_rate": float(search.cv_results_["param_model__learning_rate"][index]),
            "l2_leaf_reg": float(search.cv_results_["param_model__l2_leaf_reg"][index]),
            "cv_pr_auc_ovr": round(float(search.cv_results_["mean_test_score"][index]), 4),
        }
        results.append(item)

    return best_params, sorted(results, key=lambda item: float(item["cv_pr_auc_ovr"]), reverse=True)


def run_local_cv_search(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    train_groups: pd.Series,
    seed_params: dict[str, float | int],
) -> tuple[dict[str, float | int], list[dict[str, float | int]]]:
    preprocessor = build_preprocessor(X_train)
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", build_estimator(seed_params)),
        ]
    )
    seed_iterations = int(seed_params["iterations"])
    seed_depth = int(seed_params["depth"])
    seed_learning_rate = float(seed_params["learning_rate"])
    seed_l2 = float(seed_params["l2_leaf_reg"])
    param_distributions = {
        "model__iterations": randint(max(150, seed_iterations - 100), seed_iterations + 151),
        "model__depth": randint(max(4, seed_depth - 2), min(10, seed_depth + 3)),
        "model__learning_rate": uniform(max(0.02, seed_learning_rate - 0.02), 0.04),
        "model__l2_leaf_reg": uniform(max(1.0, seed_l2 - 2.0), 4.0),
        "model__random_strength": uniform(0.0, 3.0),
        "model__bagging_temperature": uniform(0.0, 2.0),
    }
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
    search = RandomizedSearchCV(
        estimator=pipeline,
        param_distributions=param_distributions,
        n_iter=18,
        scoring=pr_auc_scorer,
        cv=splitter,
        refit=True,
        n_jobs=1,
        verbose=0,
        return_train_score=False,
        random_state=42,
    )
    search.fit(X_train, y_train, groups=train_groups, model__sample_weight=sample_weights)

    best_params = {
        "iterations": int(search.best_params_["model__iterations"]),
        "depth": int(search.best_params_["model__depth"]),
        "learning_rate": float(search.best_params_["model__learning_rate"]),
        "l2_leaf_reg": float(search.best_params_["model__l2_leaf_reg"]),
        "random_strength": float(search.best_params_["model__random_strength"]),
        "bagging_temperature": float(search.best_params_["model__bagging_temperature"]),
    }

    results: list[dict[str, float | int]] = []
    for index in range(len(search.cv_results_["params"])):
        item = {
            "iterations": int(search.cv_results_["param_model__iterations"][index]),
            "depth": int(search.cv_results_["param_model__depth"][index]),
            "learning_rate": float(search.cv_results_["param_model__learning_rate"][index]),
            "l2_leaf_reg": float(search.cv_results_["param_model__l2_leaf_reg"][index]),
            "random_strength": round(float(search.cv_results_["param_model__random_strength"][index]), 4),
            "bagging_temperature": round(float(search.cv_results_["param_model__bagging_temperature"][index]), 4),
            "cv_pr_auc_ovr": round(float(search.cv_results_["mean_test_score"][index]), 4),
        }
        results.append(item)

    return best_params, sorted(results, key=lambda item: float(item["cv_pr_auc_ovr"]), reverse=True)


def render_markdown(
    split_summary: dict[str, object],
    baseline_result: dict[str, object],
    tuned_result: dict[str, object],
    hybrid_result: dict[str, object],
    coarse_best_params: dict[str, float | int],
    best_params: dict[str, float | int],
    coarse_cv_results: list[dict[str, float | int]],
    cv_results: list[dict[str, float | int]],
) -> str:
    lines = [
        "# CatBoost Hyperparameter Tuning",
        "",
        "## Split Protocol",
        "",
        f"- Type: {split_summary['split_type']}",
        f"- Train groups: {split_summary['train_groups']}",
        f"- Test groups: {split_summary['test_groups']}",
        f"- Train rows: {split_summary['train_rows']}",
        f"- Test rows: {split_summary['test_rows']}",
        "- Search method: GridSearchCV",
        "- CV protocol: StratifiedGroupKFold by session_id",
        "- Selection metric: PR-AUC OVR",
        "- Search strategy: coarse grid + randomized local refinement",
        "",
        "## Best Parameters",
        "",
        f"- Best parameters after coarse search: `{coarse_best_params}`",
        f"- Best parameters after local refinement: `{best_params}`",
        "",
        "## Test Metrics",
        "",
        "| Model | Balanced Accuracy | Macro Precision | Macro Recall | PR-AUC OVR | ROC-AUC OVR |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]

    for row in (baseline_result, tuned_result, hybrid_result):
        lines.append(
            f"| {row['model']} | {row['balanced_accuracy']:.4f} | {row['macro_precision']:.4f} | {row['macro_recall']:.4f} | {row['pr_auc_ovr']:.4f} | {row['roc_auc_ovr']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Top Coarse Grid Configurations",
            "",
            "| iterations | depth | learning_rate | l2_leaf_reg | CV PR-AUC OVR |",
            "| ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in coarse_cv_results[:10]:
        lines.append(
            f"| {row['iterations']} | {row['depth']} | {row['learning_rate']:.2f} | {row['l2_leaf_reg']} | {row['cv_pr_auc_ovr']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Top Local Refinement Configurations",
            "",
            "| iterations | depth | learning_rate | l2_leaf_reg | random_strength | bagging_temperature | CV PR-AUC OVR |",
            "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in cv_results[:10]:
        lines.append(
            f"| {row['iterations']} | {row['depth']} | {row['learning_rate']:.4f} | {row['l2_leaf_reg']:.4f} | {row['random_strength']:.4f} | {row['bagging_temperature']:.4f} | {row['cv_pr_auc_ovr']:.4f} |"
        )

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "data" / "synthetic_mcp_events.csv"
    reports_dir = project_root / "reports"

    df = load_dataset(dataset_path)
    X, y = split_features(df)
    groups = df[GROUP_COLUMN]

    train_idx, test_idx = grouped_split(X, y, groups)
    split_summary = summarize_split(df, train_idx, test_idx)

    X_train = X.iloc[train_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    y_train = y.iloc[train_idx].reset_index(drop=True)
    y_test = y.iloc[test_idx].reset_index(drop=True)
    train_groups = groups.iloc[train_idx].reset_index(drop=True)
    test_rows = df.iloc[test_idx].reset_index(drop=True)

    coarse_best_params, coarse_cv_results = run_cv_search(X_train, y_train, train_groups)
    best_params, cv_results = run_local_cv_search(X_train, y_train, train_groups, coarse_best_params)

    preprocessor = build_preprocessor(X_train)
    baseline_pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", build_estimator({"iterations": 300, "depth": 6, "learning_rate": 0.05, "l2_leaf_reg": 3})),
        ]
    )
    tuned_pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", build_estimator(best_params)),
        ]
    )

    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
    baseline_pipeline.fit(X_train, y_train, model__sample_weight=sample_weights)
    tuned_pipeline.fit(X_train, y_train, model__sample_weight=sample_weights)

    baseline_pred = pd.Series(flatten_predictions(baseline_pipeline.predict(X_test)), index=y_test.index)
    baseline_score = align_proba(baseline_pipeline.predict_proba(X_test), baseline_pipeline.named_steps["model"].classes_)
    tuned_pred = pd.Series(flatten_predictions(tuned_pipeline.predict(X_test)), index=y_test.index)
    tuned_score = align_proba(tuned_pipeline.predict_proba(X_test), tuned_pipeline.named_steps["model"].classes_)

    baseline_result = evaluate_classifier("CatBoost baseline", y_test, baseline_pred, baseline_score)
    tuned_result = evaluate_classifier("CatBoost tuned", y_test, tuned_pred, tuned_score)

    hybrid_rule_pred = build_hybrid_rule_predictions(test_rows)
    hybrid_pred, hybrid_score = build_hybrid_predictions(hybrid_rule_pred, tuned_pred, tuned_score)
    hybrid_result = evaluate_classifier("Hybrid Rules + CatBoost tuned", y_test, hybrid_pred, hybrid_score)

    tuning_json = {
        "coarse_best_params": coarse_best_params,
        "best_params": best_params,
        "coarse_cv_results": coarse_cv_results,
        "cv_results": cv_results,
        "baseline_result": baseline_result,
        "tuned_result": tuned_result,
        "hybrid_result": hybrid_result,
    }

    md_path = reports_dir / "catboost_tuning.md"
    json_path = reports_dir / "catboost_tuning.json"
    md_path.write_text(
        render_markdown(
            split_summary,
            baseline_result,
            tuned_result,
            hybrid_result,
            coarse_best_params,
            best_params,
            coarse_cv_results,
            cv_results,
        ),
        encoding="utf-8",
    )
    json_path.write_text(json.dumps(tuning_json, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"CatBoost tuning report: {md_path}")
    print(f"CatBoost tuning JSON: {json_path}")
    print(f"Best params: {best_params}")
    for row in (baseline_result, tuned_result, hybrid_result):
        print(
            f"{row['model']}: balanced_accuracy={row['balanced_accuracy']:.4f}, "
            f"macro_precision={row['macro_precision']:.4f}, "
            f"macro_recall={row['macro_recall']:.4f}, "
            f"pr_auc_ovr={row['pr_auc_ovr']:.4f}, "
            f"roc_auc_ovr={row['roc_auc_ovr']:.4f}"
        )


if __name__ == "__main__":
    main()
