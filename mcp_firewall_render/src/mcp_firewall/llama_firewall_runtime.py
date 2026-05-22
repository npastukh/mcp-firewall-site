from __future__ import annotations

from dataclasses import dataclass

from mcp_firewall.models import MCPEvent
from mcp_firewall.privacy_filter_runtime import render_event_as_text


@dataclass(slots=True)
class LlamaFirewallAssessment:
    context_text: str
    decision: str
    reason: str
    score: float
    scanners: tuple[str, ...]


class LlamaFirewallEvaluator:
    def __init__(
        self,
        scanners: tuple[str, ...] = ("PROMPT_GUARD",),
        role_name: str = "USER",
    ) -> None:
        self._scanner_names = tuple(scanner.strip().upper() for scanner in scanners if scanner.strip())
        self._role_name = role_name.strip().upper()
        self._firewall = None
        self._message_type = None

    def _load(self) -> None:
        if self._firewall is not None and self._message_type is not None:
            return

        try:
            from llamafirewall import LlamaFirewall, Role, ScannerType, UserMessage
        except ImportError as exc:
            raise RuntimeError(
                "LlamaFirewall runtime requires the `llamafirewall` package. "
                "Install it with `python3 -m pip install -e '.[llama-firewall]'` "
                "and run `llamafirewall configure` to preload the guard models."
            ) from exc

        try:
            role = getattr(Role, self._role_name)
        except AttributeError as exc:
            raise RuntimeError(f"Unsupported LlamaFirewall role: {self._role_name}") from exc

        scanners = []
        for scanner_name in self._scanner_names:
            try:
                scanners.append(getattr(ScannerType, scanner_name))
            except AttributeError as exc:
                raise RuntimeError(f"Unsupported LlamaFirewall scanner: {scanner_name}") from exc

        scanner_config = {role: scanners}
        try:
            self._firewall = LlamaFirewall(scanners=scanner_config)
        except TypeError:
            self._firewall = LlamaFirewall(scanner_config)
        self._message_type = UserMessage

    def evaluate_text(self, text: str) -> LlamaFirewallAssessment:
        self._load()
        result = self._firewall.scan(self._message_type(content=text))
        decision = self._normalize_decision(getattr(result, "decision", "allow"))
        reason = str(getattr(result, "reason", "default"))
        score = float(getattr(result, "score", 0.0))
        return LlamaFirewallAssessment(
            context_text=text,
            decision=decision,
            reason=reason,
            score=round(score, 4),
            scanners=self._scanner_names,
        )

    def evaluate_event(self, event: MCPEvent) -> LlamaFirewallAssessment:
        return self.evaluate_text(render_event_as_text(event))

    @staticmethod
    def _normalize_decision(decision: object) -> str:
        raw_value = getattr(decision, "value", decision)
        return str(raw_value).strip().lower() or "allow"
