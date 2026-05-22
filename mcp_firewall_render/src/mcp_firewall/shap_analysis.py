from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib-codex")

import numpy as np
import shap
from PIL import Image, ImageDraw, ImageFont
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from mcp_firewall.train_models import load_dataset, split_features


def _extract_positive_class_values(explanation: shap.Explanation) -> np.ndarray:
    values = explanation.values
    if values.ndim == 3:
        return values[:, :, 1]
    return values


def _build_preprocessor(X_train) -> ColumnTransformer:
    categorical_cols = X_train.select_dtypes(include=["object", "str", "bool"]).columns.tolist()
    numeric_cols = [column for column in X_train.columns if column not in categorical_cols]

    return ColumnTransformer(
        transformers=[
            ("categorical", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("numeric", StandardScaler(), numeric_cols),
        ]
    )


def _build_random_forest_pipeline(X_train):
    preprocessor = _build_preprocessor(X_train)
    estimator = RandomForestClassifier(
        n_estimators=250,
        max_depth=10,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
    )
    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", estimator),
        ]
    )


def render_markdown(items: list[dict[str, float | str]]) -> str:
    lines = [
        "# SHAP Feature Importance for Random Forest",
        "",
        "| Feature | Mean |SHAP| |",
        "| --- | ---: |",
    ]
    for item in items:
        lines.append(f"| {item['feature']} | {item['mean_abs_shap']:.4f} |")
    lines.append("")
    lines.append(
        "Значения получены как среднее абсолютное значение SHAP по тестовой выборке для положительного класса."
    )
    return "\n".join(lines)


def _prettify_feature_name(name: str) -> str:
    mapping = {
        "feature_response_size": "response_size",
        "feature_response_time_ms": "response_time_ms",
        "feature_tool_name_filesystem.search": "tool=filesystem.search",
        "feature_tool_name_filesystem.read_file": "tool=filesystem.read_file",
        "feature_sensitive_keyword_flag_True": "sensitive_keyword=True",
        "feature_sensitive_keyword_flag_False": "sensitive_keyword=False",
        "feature_private_ip_flag_True": "private_ip=True",
        "feature_payload_size": "payload_size",
        "feature_arg_count": "arg_count",
        "feature_transport_type_stdio": "transport=stdio",
    }
    return mapping.get(name, name.replace("feature_", ""))


def plot_bar(
    items: list[dict[str, float | str]],
    output_path: Path,
    *,
    title: str = "SHAP importance for Random Forest",
    subtitle: str = "Mean absolute SHAP value on test sample",
    compact_labels: bool = False,
    width: int = 1400,
    height: int = 900,
    font_scale: float = 1.0,
) -> None:
    labels = [str(item["feature"]) for item in items][::-1]
    values = [float(item["mean_abs_shap"]) for item in items][::-1]
    if compact_labels:
        labels = [_prettify_feature_name(label) for label in labels]

    margin_left = 430
    margin_right = 120
    margin_top = 120
    margin_bottom = 80
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    row_height = plot_height / max(len(labels), 1)
    max_value = max(values) if values else 1.0

    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    try:
        title_font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", int(32 * font_scale))
        subtitle_font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", int(18 * font_scale))
        body_font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", int(20 * font_scale))
    except OSError:
        title_font = ImageFont.load_default()
        subtitle_font = ImageFont.load_default()
        body_font = ImageFont.load_default()

    draw.text((margin_left, 30), title, fill="#1E3E82", font=title_font)
    draw.text((margin_left, 72), subtitle, fill="#555555", font=subtitle_font)

    axis_y = height - margin_bottom
    draw.line((margin_left, margin_top, margin_left, axis_y), fill="#AAB7D1", width=2)
    draw.line((margin_left, axis_y, width - margin_right, axis_y), fill="#AAB7D1", width=2)

    for tick_index in range(6):
        tick_value = max_value * tick_index / 5
        tick_x = margin_left + int(plot_width * tick_index / 5)
        draw.line((tick_x, axis_y, tick_x, axis_y + 8), fill="#AAB7D1", width=1)
        draw.text((tick_x - 10, axis_y + 12), f"{tick_value:.2f}", fill="#555555", font=body_font)

    for index, (label, value) in enumerate(zip(labels, values, strict=False)):
        top = margin_top + int(index * row_height + row_height * 0.2)
        bar_height = int(row_height * 0.6)
        bar_width = int((value / max_value) * plot_width) if max_value else 0
        draw.rounded_rectangle(
            (
                margin_left,
                top,
                margin_left + bar_width,
                top + bar_height,
            ),
            radius=8,
            fill="#2952A3",
        )
        draw.text((40, top + bar_height / 4), label, fill="#1E3E82", font=body_font)
        draw.text((margin_left + bar_width + 14, top + bar_height / 4), f"{value:.3f}", fill="#333333", font=body_font)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "data" / "synthetic_mcp_events.csv"
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    df = load_dataset(dataset_path)
    X, y = split_features(df)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    pipeline = _build_random_forest_pipeline(X_train)
    pipeline.fit(X_train, y_train)

    preprocessor = pipeline.named_steps["preprocessor"]
    model = pipeline.named_steps["model"]
    transformed_test = preprocessor.transform(X_test)
    if hasattr(transformed_test, "toarray"):
        transformed_test = transformed_test.toarray()
    feature_names = [
        name.replace("categorical__", "").replace("numeric__", "")
        for name in preprocessor.get_feature_names_out()
    ]

    sample_size = min(300, transformed_test.shape[0])
    transformed_sample = transformed_test[:sample_size]

    explainer = shap.TreeExplainer(model)
    explanation = explainer(transformed_sample)
    positive_values = _extract_positive_class_values(explanation)
    mean_abs = np.abs(positive_values).mean(axis=0)

    order = np.argsort(mean_abs)[::-1][:10]
    items = [
        {
            "feature": feature_names[idx],
            "mean_abs_shap": round(float(mean_abs[idx]), 4),
        }
        for idx in order
    ]

    md_path = reports_dir / "shap_feature_importance.md"
    json_path = reports_dir / "shap_feature_importance.json"
    png_path = reports_dir / "shap_feature_importance.png"
    presentation_png_path = reports_dir / "shap_feature_importance_top5_presentation.png"

    md_path.write_text(render_markdown(items), encoding="utf-8")
    json_path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    plot_bar(items, png_path)
    plot_bar(
        items[:5],
        presentation_png_path,
        title="Top-5 SHAP features for Random Forest",
        subtitle="Mean |SHAP| on test sample",
        compact_labels=True,
        width=1600,
        height=900,
        font_scale=1.15,
    )

    print(md_path)
    print(json_path)
    print(png_path)
    print(presentation_png_path)


if __name__ == "__main__":
    main()
