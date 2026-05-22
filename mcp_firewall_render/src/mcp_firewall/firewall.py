from __future__ import annotations

from mcp_firewall.access_control import AccessControlEngine
from mcp_firewall.catboost_runtime import CatBoostRuntimeModel
from mcp_firewall.config import FirewallConfig
from mcp_firewall.decision_engine import DecisionEngine
from mcp_firewall.feature_extractor import FeatureExtractor
from mcp_firewall.logger import JsonlLogger
from mcp_firewall.ml_engine import HeuristicRiskModel
from mcp_firewall.models import AnalysisResult, MCPEvent, PrivacyAssessment, SessionState
from mcp_firewall.privacy_filter_runtime import HIGH_RISK_PRIVACY_LABELS, PrivacyFilterEvaluator
from mcp_firewall.rule_engine import RuleEngine


class FirewallService:
    def __init__(
        self,
        config: FirewallConfig,
        logger: JsonlLogger | None = None,
        privacy_evaluator: PrivacyFilterEvaluator | None = None,
    ) -> None:
        self._config = config
        self._access_control = AccessControlEngine(config)
        self._rule_engine = RuleEngine(config)
        self._feature_extractor = FeatureExtractor(config)
        self._risk_model = self._build_risk_model()
        self._decision_engine = DecisionEngine(config)
        self._logger = logger
        self._sessions: dict[str, SessionState] = {}
        self._privacy_evaluator = privacy_evaluator or self._build_privacy_evaluator()

    def process_event(self, event: MCPEvent) -> AnalysisResult:
        state = self._sessions.setdefault(event.session_id, SessionState(session_id=event.session_id))
        features = self._feature_extractor.extract(event, state)
        privacy_assessment = self._evaluate_privacy(event)
        if privacy_assessment is not None:
            features.update(self._privacy_features(privacy_assessment))
        access_matches = self._access_control.evaluate(event)
        rule_matches = [*access_matches, *self._rule_engine.evaluate(event, state, privacy_assessment)]
        supervised_assessment = None
        if isinstance(self._risk_model, CatBoostRuntimeModel):
            supervised_assessment = self._risk_model.predict(features)
            risk_score = supervised_assessment.risk_score
        else:
            risk_score = self._risk_model.score(features, state)
        result = self._decision_engine.decide(
            risk_score,
            rule_matches,
            features,
            supervised_assessment=supervised_assessment,
            privacy_assessment=privacy_assessment,
        )
        self._update_state(event, state, features)
        if self._logger:
            self._logger.write(event, result, state)
        return result

    def _build_risk_model(self) -> HeuristicRiskModel | CatBoostRuntimeModel:
        if self._config.supervised_runtime_enabled and self._config.supervised_model_path:
            return CatBoostRuntimeModel(self._config.supervised_model_path)
        return HeuristicRiskModel()

    def _build_privacy_evaluator(self) -> PrivacyFilterEvaluator | None:
        if not self._config.full_context_evaluator_enabled:
            return None
        if not self._config.full_context_model_path:
            return None
        return PrivacyFilterEvaluator(
            model_path=self._config.full_context_model_path,
            max_length=self._config.full_context_max_length,
            extraction_threshold=self._config.full_context_extraction_threshold,
        )

    def _evaluate_privacy(self, event: MCPEvent) -> PrivacyAssessment | None:
        if self._privacy_evaluator is None:
            return None
        return self._privacy_evaluator.evaluate_event(event)

    def _privacy_features(self, assessment: PrivacyAssessment) -> dict[str, float | int | str | bool]:
        high_risk_detected = any(span.label in HIGH_RISK_PRIVACY_LABELS for span in assessment.spans)
        return {
            "full_context_sensitive_flag": bool(assessment.entity_count),
            "full_context_high_risk_flag": high_risk_detected,
            "full_context_entity_count": assessment.entity_count,
            "full_context_sensitive_entity_count": assessment.sensitive_entity_count,
            "full_context_max_confidence": assessment.max_confidence,
        }

    def _update_state(
        self,
        event: MCPEvent,
        state: SessionState,
        features: dict[str, float | int | str | bool],
    ) -> None:
        state.total_calls += 1
        if event.is_error:
            state.failed_calls += 1
        if event.tool_name:
            state.tools_called.append(event.tool_name)
            state.last_tool_name = event.tool_name
        if (
            bool(features["sensitive_path_flag"])
            or bool(features["private_ip_flag"])
            or bool(features.get("full_context_sensitive_flag", False))
        ):
            state.sensitive_hits += 1
