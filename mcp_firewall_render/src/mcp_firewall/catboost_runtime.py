from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import load

from mcp_firewall.models import SupervisedAssessment


@dataclass(slots=True)
class RuntimeArtifactPaths:
    pipeline_path: Path
    manifest_path: Path


class CatBoostRuntimeModel:
    def __init__(self, model_path: str | Path) -> None:
        artifact_paths = self._resolve_paths(Path(model_path))
        self._pipeline = load(artifact_paths.pipeline_path)
        self._manifest = json.loads(artifact_paths.manifest_path.read_text(encoding="utf-8"))
        self._feature_columns = list(self._manifest["feature_columns"])
        self._class_labels = list(self._manifest["class_labels"])
        self._model_name = str(self._manifest.get("model_name", "CatBoost"))

    @property
    def model_name(self) -> str:
        return self._model_name

    def predict(self, features: dict[str, float | int | str | bool]) -> SupervisedAssessment:
        runtime_row = {
            column: features.get(column.removeprefix("feature_"))
            for column in self._feature_columns
        }
        frame = pd.DataFrame([runtime_row], columns=self._feature_columns)

        probabilities = self._pipeline.predict_proba(frame)[0]
        predicted_class_id = int(np.asarray(self._pipeline.predict(frame)).reshape(-1)[0])
        probability_map = {
            label: round(float(probability), 6)
            for label, probability in zip(self._class_labels, probabilities, strict=False)
        }

        return SupervisedAssessment(
            model_name=self._model_name,
            predicted_label=self._class_labels[predicted_class_id],
            predicted_class_id=predicted_class_id,
            probabilities=probability_map,
            risk_score=self._to_risk_score(probability_map),
        )

    def _resolve_paths(self, model_path: Path) -> RuntimeArtifactPaths:
        if model_path.is_dir():
            return RuntimeArtifactPaths(
                pipeline_path=model_path / "catboost_pipeline.joblib",
                manifest_path=model_path / "runtime_manifest.json",
            )
        return RuntimeArtifactPaths(
            pipeline_path=model_path,
            manifest_path=model_path.with_name("runtime_manifest.json"),
        )

    def _to_risk_score(self, probabilities: dict[str, float]) -> float:
        anomalous = probabilities.get("anomalous", 0.0)
        malicious = probabilities.get("malicious", 0.0)
        return round(float(0.5 * anomalous + 1.0 * malicious), 6)


def resolve_runtime_artifact_dir(project_root: Path) -> Path | None:
    candidate = project_root / "artifacts" / "runtime"
    pipeline_path = candidate / "catboost_pipeline.joblib"
    manifest_path = candidate / "runtime_manifest.json"
    if pipeline_path.exists() and manifest_path.exists():
        return candidate
    return None
