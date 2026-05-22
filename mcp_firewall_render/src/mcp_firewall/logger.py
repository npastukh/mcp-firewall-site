from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from mcp_firewall.models import AnalysisResult, MCPEvent, SessionState


class JsonlLogger:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: MCPEvent, result: AnalysisResult, state: SessionState) -> None:
        record = {
            "event": {
                **asdict(event),
                "timestamp": event.timestamp.isoformat(),
            },
            "analysis": {
                "risk_score": result.risk_score,
                "decision": result.decision,
                "rationale": result.rationale,
                "rule_matches": [asdict(match) for match in result.rule_matches],
                "rule_names": [match.name for match in result.rule_matches],
                "features": result.features,
                "supervised_assessment": asdict(result.supervised_assessment) if result.supervised_assessment else None,
                "privacy_assessment": asdict(result.privacy_assessment) if result.privacy_assessment else None,
            },
            "session": {
                "session_id": state.session_id,
                "total_calls": state.total_calls,
                "failed_calls": state.failed_calls,
                "last_tool_name": state.last_tool_name,
                "sensitive_hits": state.sensitive_hits,
            },
        }
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
