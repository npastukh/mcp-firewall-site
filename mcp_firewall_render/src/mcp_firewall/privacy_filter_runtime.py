from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_firewall.gliner2_dataset import (
    GLINER2_CLASSIFICATION_DESCRIPTIONS,
    GLINER2_CLASSIFICATION_LABELS,
    GLINER2_CLASSIFICATION_TASK,
    GLINER2_ENTITY_DESCRIPTIONS,
)
from mcp_firewall.models import MCPEvent, PrivacyAssessment, PrivacyEntitySpan

TOKEN_PATTERN = re.compile(r"[^\s=,:;{}\[\]()]+|[=,:;{}\[\]()]")
HIGH_RISK_PRIVACY_LABELS = frozenset(
    {
        "secret",
        "password",
        "token",
        "env_access_pattern",
        "secret_name",
        "secret_value",
        "sensitive_path",
        "private_host",
        "secret_store_ref",
        "account_number",
        "url",
        "path",
        "private_path",
    }
)


def _is_gliner2_checkpoint(path_or_name: str) -> bool:
    checkpoint_path = Path(path_or_name)
    if checkpoint_path.is_dir():
        config_path = checkpoint_path / "config.json"
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return False
            if config.get("model_type") == "extractor":
                return True
        if (checkpoint_path / "encoder_config" / "config.json").exists():
            return True
    return "gliner2" in path_or_name.lower()


def _normalize_hf_repo_id(base_model_name_or_path: str) -> str:
    candidate = base_model_name_or_path.strip().strip("/").replace("\\", "/")
    if not candidate:
        return base_model_name_or_path
    if "/" in candidate and not candidate.startswith("artifacts/models/"):
        return candidate

    model_name = Path(candidate).name
    parts = model_name.split("_", 1)
    if len(parts) == 2:
        namespace, repo_name = parts
        return f"{namespace}/{repo_name.replace('_', '-')}"
    return candidate


def _resolve_base_model_reference(model_path: Path, base_model_name_or_path: str) -> str:
    raw_value = base_model_name_or_path.strip()
    if not raw_value:
        return base_model_name_or_path

    base_path = Path(raw_value)
    if base_path.is_absolute() and base_path.exists():
        return str(base_path)

    search_roots = (Path.cwd(), model_path, *model_path.parents)
    for root in search_roots:
        candidate = (root / base_path).resolve()
        if candidate.exists():
            return str(candidate)

    return _normalize_hf_repo_id(raw_value)


def _joined_token_offsets(tokens: list[str]) -> list[tuple[int, int]]:
    offsets: list[tuple[int, int]] = []
    cursor = 0
    for index, token in enumerate(tokens):
        if index:
            cursor += 1
        start = cursor
        cursor += len(token)
        offsets.append((start, cursor))
    return offsets


def _char_span_to_token_span(
    token_offsets: list[tuple[int, int]],
    start_char: int,
    end_char: int,
) -> tuple[int, int] | None:
    overlapping = [
        index
        for index, (token_start, token_end) in enumerate(token_offsets)
        if token_start < end_char and token_end > start_char
    ]
    if not overlapping:
        return None
    return overlapping[0], overlapping[-1]


def _build_gliner2_schema() -> dict[str, object]:
    return {
        "entities": GLINER2_ENTITY_DESCRIPTIONS,
        "classifications": [
            {
                "task": GLINER2_CLASSIFICATION_TASK,
                "labels": list(GLINER2_CLASSIFICATION_LABELS),
                "label_descriptions": GLINER2_CLASSIFICATION_DESCRIPTIONS,
            }
        ],
    }


def _extract_request_safety_label(value: object) -> str | None:
    if isinstance(value, str) and value in GLINER2_CLASSIFICATION_LABELS:
        return value
    if isinstance(value, list) and len(value) == 1:
        only = value[0]
        if isinstance(only, str) and only in GLINER2_CLASSIFICATION_LABELS:
            return only
    if isinstance(value, dict):
        for key in ("predicted_label", "label", "top_label", "value"):
            nested = _extract_request_safety_label(value.get(key))
            if nested is not None:
                return nested
    return None


def _iter_candidate_dicts(payload: object) -> list[dict[str, object]]:
    stack = [payload]
    candidates: list[dict[str, object]] = []
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            candidates.append(current)
            for value in current.values():
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(current, list):
            for value in current:
                if isinstance(value, (dict, list)):
                    stack.append(value)
    return candidates


def _predict_request_safety(payload: dict[str, object], *, fallback_label: str) -> str:
    classifications = payload.get("classifications")
    for candidate in _iter_candidate_dicts(classifications):
        task_name = str(candidate.get("task", "")).strip()
        if task_name and task_name != GLINER2_CLASSIFICATION_TASK:
            continue
        for key in ("predicted_label", "label", "top_label", "prediction", "value"):
            label = _extract_request_safety_label(candidate.get(key))
            if label is not None:
                return label
        label = _extract_request_safety_label(candidate.get(GLINER2_CLASSIFICATION_TASK))
        if label is not None:
            return label
    return fallback_label


def _flatten_param_items(payload: Any, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(payload, dict):
        items: list[tuple[str, str]] = []
        for key, value in payload.items():
            key_prefix = f"{prefix}.{key}" if prefix else str(key)
            items.extend(_flatten_param_items(value, key_prefix))
        return items
    if isinstance(payload, list):
        items = []
        for index, value in enumerate(payload):
            list_prefix = f"{prefix}[{index}]"
            items.extend(_flatten_param_items(value, list_prefix))
        return items
    if payload is None:
        return [(prefix or "value", "null")]
    return [(prefix or "value", str(payload))]


def tokenize_context_text(text: str) -> list[str]:
    if " " not in text and (
        text.startswith(("http://", "https://"))
        or "@" in text
        or text.startswith("+7-")
        or text.startswith(("sk-proj-", "tok_", "tok_live_", "ghp_", "xoxb-", "ya29.", "pwd_demo_"))
    ):
        return [text]
    return TOKEN_PATTERN.findall(text)


def render_event_as_tokens(event: MCPEvent) -> list[str]:
    tokens = [
        "client_id",
        "=",
        event.client_id,
        "server_id",
        "=",
        event.server_id,
        "transport",
        "=",
        event.transport_type,
        "method",
        "=",
        event.jsonrpc_method,
    ]
    if event.tool_name:
        tokens.extend(["tool_name", "=", event.tool_name])
    if event.resource_name:
        tokens.extend(["resource_name", "=", event.resource_name])
    if event.prompt_name:
        tokens.extend(["prompt_name", "=", event.prompt_name])

    for key, value in _flatten_param_items(event.params):
        tokens.extend([key, "=", *tokenize_context_text(value)])
    return tokens


def render_event_as_text(event: MCPEvent) -> str:
    return " ".join(render_event_as_tokens(event))


def _normalize_bioes_predictions(
    tokens: list[str],
    predicted_tags: list[str],
    scores: list[float],
) -> list[PrivacyEntitySpan]:
    spans: list[PrivacyEntitySpan] = []
    active_label: str | None = None
    active_tokens: list[str] = []
    active_scores: list[float] = []
    active_start = 0

    def flush_active() -> None:
        nonlocal active_label, active_tokens, active_scores, active_start
        if active_label is None:
            return
        spans.append(
            PrivacyEntitySpan(
                label=active_label,
                text=" ".join(active_tokens),
                score=round(sum(active_scores) / len(active_scores), 4),
                start_token=active_start,
                end_token=active_start + len(active_tokens) - 1,
            )
        )
        active_label = None
        active_tokens = []
        active_scores = []
        active_start = 0

    for index, (token, tag, score) in enumerate(zip(tokens, predicted_tags, scores, strict=True)):
        if tag == "O":
            flush_active()
            continue

        prefix, label = tag.split("-", 1)
        if prefix == "S":
            flush_active()
            spans.append(
                PrivacyEntitySpan(
                    label=label,
                    text=token,
                    score=round(score, 4),
                    start_token=index,
                    end_token=index,
                )
            )
            continue

        if prefix == "B":
            flush_active()
            active_label = label
            active_tokens = [token]
            active_scores = [score]
            active_start = index
            continue

        if prefix == "I":
            if active_label != label:
                flush_active()
                active_label = label
                active_tokens = [token]
                active_scores = [score]
                active_start = index
                continue
            active_tokens.append(token)
            active_scores.append(score)
            continue

        if prefix == "E":
            if active_label != label:
                spans.append(
                    PrivacyEntitySpan(
                        label=label,
                        text=token,
                        score=round(score, 4),
                        start_token=index,
                        end_token=index,
                    )
                )
                continue
            active_tokens.append(token)
            active_scores.append(score)
            flush_active()
            continue

    flush_active()
    return spans


class PrivacyFilterEvaluator:
    def __init__(
        self,
        model_path: str,
        max_length: int = 128,
        extraction_threshold: float = 0.5,
    ) -> None:
        self._model_path = model_path
        self._max_length = max_length
        self._extraction_threshold = extraction_threshold
        self._tokenizer = None
        self._model = None
        self._device = None
        self._runtime_kind = "token-classification"

    def _load(self) -> None:
        if self._model is not None and self._tokenizer is not None:
            return

        model_path = Path(self._model_path)
        if model_path.exists() and (model_path / "adapter_config.json").exists():
            adapter_config = json.loads((model_path / "adapter_config.json").read_text(encoding="utf-8"))
            if _is_gliner2_checkpoint(str(adapter_config.get("base_model_name_or_path", ""))):
                self._load_gliner2(adapter_only=True)
                return
        if _is_gliner2_checkpoint(self._model_path):
            self._load_gliner2(adapter_only=False)
            return

        try:
            import torch
            from transformers import AutoModelForTokenClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Privacy filter runtime requires torch and transformers>=5.8.1. Install the privacy-filter dependencies first."
            ) from exc

        self._tokenizer = AutoTokenizer.from_pretrained(self._model_path)
        if (model_path / "adapter_config.json").exists():
            try:
                from peft import PeftConfig, PeftModel
            except ImportError as exc:
                raise RuntimeError(
                    "This checkpoint uses LoRA adapters. Install peft to run the privacy filter runtime."
                ) from exc

            peft_config = PeftConfig.from_pretrained(self._model_path)
            base_model_kwargs: dict[str, object] = {}
            label_schema_path = model_path / "label_schema.json"
            if label_schema_path.exists():
                schema = json.loads(label_schema_path.read_text(encoding="utf-8"))
                id_to_label = {
                    int(index): label
                    for index, label in schema.get("id_to_label", {}).items()
                }
                base_model_kwargs.update(
                    {
                        "num_labels": len(schema.get("ner_labels", [])),
                        "id2label": id_to_label,
                        "label2id": schema.get("label_to_id", {}),
                        "ignore_mismatched_sizes": True,
                    }
                )
            base_model = AutoModelForTokenClassification.from_pretrained(
                peft_config.base_model_name_or_path,
                **base_model_kwargs,
            )
            self._model = PeftModel.from_pretrained(base_model, self._model_path)
        else:
            self._model = AutoModelForTokenClassification.from_pretrained(self._model_path)
        if torch.cuda.is_available():
            self._device = torch.device("cuda")
        elif torch.backends.mps.is_available():
            self._device = torch.device("mps")
        else:
            self._device = torch.device("cpu")
        self._model.to(self._device)
        self._model.eval()
        self._runtime_kind = "token-classification"

    def _load_gliner2(self, adapter_only: bool) -> None:
        try:
            import torch
            from gliner2 import GLiNER2
        except ImportError as exc:
            raise RuntimeError(
                "GLiNER2 runtime requires `gliner2`. Install the GLiNER2 dependencies first."
            ) from exc

        model_path = Path(self._model_path)
        if adapter_only:
            try:
                from peft import PeftConfig, PeftModel
            except ImportError as exc:
                raise RuntimeError(
                    "This GLiNER2 checkpoint uses LoRA adapters. Install peft to run the privacy filter runtime."
                ) from exc
            peft_config = PeftConfig.from_pretrained(self._model_path)
            base_model_reference = _resolve_base_model_reference(
                model_path=model_path,
                base_model_name_or_path=peft_config.base_model_name_or_path,
            )
            base_model = GLiNER2.from_pretrained(base_model_reference)
            self._model = PeftModel.from_pretrained(base_model, self._model_path)
            self._tokenizer = getattr(base_model.processor, "tokenizer", None)
        else:
            self._model = GLiNER2.from_pretrained(self._model_path)
            self._tokenizer = getattr(self._model.processor, "tokenizer", None)

        if torch.cuda.is_available():
            self._device = torch.device("cuda")
        elif torch.backends.mps.is_available():
            self._device = torch.device("mps")
        else:
            self._device = torch.device("cpu")

        self._model.to(self._device)
        self._model.eval()
        self._runtime_kind = "gliner2"

    def evaluate_tokens(self, tokens: list[str]) -> PrivacyAssessment:
        self._load()
        if not tokens:
            return PrivacyAssessment("", 0.0, tuple(), 0, 0, [])

        if self._runtime_kind == "gliner2":
            return self._evaluate_tokens_gliner2(tokens)

        import torch

        encoded = self._tokenizer(
            tokens,
            is_split_into_words=True,
            truncation=True,
            max_length=self._max_length,
            return_tensors="pt",
        )
        word_ids = encoded.word_ids(batch_index=0)
        model_inputs = {
            key: value.to(self._device)
            for key, value in encoded.items()
            if hasattr(value, "to")
        }

        with torch.no_grad():
            outputs = self._model(**model_inputs)
            probabilities = torch.softmax(outputs.logits, dim=-1).cpu()[0]
            predictions = probabilities.argmax(dim=-1).tolist()

        truncated_tokens: list[str] = []
        predicted_tags: list[str] = []
        scores: list[float] = []
        previous_word_idx: int | None = None
        for token_index, word_idx in enumerate(word_ids):
            if word_idx is None or word_idx == previous_word_idx:
                previous_word_idx = word_idx
                continue
            label_id = predictions[token_index]
            label = self._model.config.id2label[label_id]
            truncated_tokens.append(tokens[word_idx])
            predicted_tags.append(label)
            scores.append(float(probabilities[token_index, label_id].item()))
            previous_word_idx = word_idx

        spans = _normalize_bioes_predictions(truncated_tokens, predicted_tags, scores)
        detected_labels = tuple(sorted({span.label for span in spans}))
        max_confidence = max((span.score for span in spans), default=0.0)
        sensitive_entity_count = sum(1 for span in spans if span.label in HIGH_RISK_PRIVACY_LABELS)
        return PrivacyAssessment(
            context_text=" ".join(truncated_tokens),
            max_confidence=round(max_confidence, 4),
            detected_labels=detected_labels,
            entity_count=len(spans),
            sensitive_entity_count=sensitive_entity_count,
            spans=spans,
        )

    def evaluate_event(self, event: MCPEvent) -> PrivacyAssessment:
        return self.evaluate_tokens(render_event_as_tokens(event))

    def _evaluate_tokens_gliner2(self, tokens: list[str]) -> PrivacyAssessment:
        text = " ".join(tokens)
        token_offsets = _joined_token_offsets(tokens)
        payload = self._model.extract(
            text,
            _build_gliner2_schema(),
            threshold=self._extraction_threshold,
            include_confidence=True,
            include_spans=True,
        )
        entities = payload.get("entities", {})
        spans: list[PrivacyEntitySpan] = []

        for label, values in entities.items():
            if not isinstance(values, list):
                continue
            for item in values:
                if not isinstance(item, dict):
                    continue
                start_char = item.get("start")
                end_char = item.get("end")
                if start_char is None or end_char is None:
                    continue
                token_span = _char_span_to_token_span(token_offsets, int(start_char), int(end_char))
                if token_span is None:
                    continue
                start_token, end_token = token_span
                spans.append(
                    PrivacyEntitySpan(
                        label=str(label),
                        text=str(item.get("text", text[int(start_char):int(end_char)])),
                        score=round(float(item.get("confidence", 0.0)), 4),
                        start_token=start_token,
                        end_token=end_token,
                    )
                )

        predicted_safety = _predict_request_safety(
            payload,
            fallback_label="suspicious" if spans else "safe",
        )
        if predicted_safety != "suspicious":
            spans = []

        spans.sort(key=lambda span: (span.start_token, span.end_token, span.label))
        detected_labels = tuple(sorted({span.label for span in spans}))
        max_confidence = max((span.score for span in spans), default=0.0)
        sensitive_entity_count = sum(1 for span in spans if span.label in HIGH_RISK_PRIVACY_LABELS)
        return PrivacyAssessment(
            context_text=text,
            max_confidence=round(max_confidence, 4),
            detected_labels=detected_labels,
            entity_count=len(spans),
            sensitive_entity_count=sensitive_entity_count,
            spans=spans,
        )
