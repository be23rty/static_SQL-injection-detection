"""Standardized Agent Protocol and Base Class for SecureCode AI.

Defines the communication contract, task models, execution modes,
and result structures across all local and online agents.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
from typing import Any, Dict, List, Optional


class ExecutionMode(str, Enum):
    LOCAL_STATIC = "LOCAL_STATIC"  # Offline, deterministic, non-LLM
    LOCAL_AI = "LOCAL_AI"          # Offline, Ollama local model
    ONLINE_AI = "ONLINE_AI"        # Cloud API (Groq / Gemini / xAI)


class AgentStatus(str, Enum):
    IDLE = "IDLE"
    WAITING = "WAITING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class AgentTask:
    task_type: str                         # e.g. 'scan', 'syntax_check', 'investigate', 'repair', 'verify'
    code: str = ""                         # Primary source code
    filename: str = "source.py"
    context: Dict[str, Any] = field(default_factory=dict)  # Project files, findings, dependencies, etc.
    preferred_mode: str = "AUTO"          # 'AUTO', 'LOCAL', 'ONLINE'
    task_id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:8]}")
    created_at: float = field(default_factory=time.time)


@dataclass
class AgentResult:
    agent_name: str
    task_id: str
    execution_mode: ExecutionMode
    status: AgentStatus
    findings: List[Dict[str, Any]] = field(default_factory=list)
    evidence: str = ""
    affected_files: List[str] = field(default_factory=list)
    line_numbers: List[int] = field(default_factory=list)
    confidence: float = 1.0
    recommendation: str = ""
    execution_time_ms: float = 0.0
    model_used: str = "None"
    handoff_to: Optional[str] = None
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "task_id": self.task_id,
            "execution_mode": self.execution_mode.value if isinstance(self.execution_mode, ExecutionMode) else str(self.execution_mode),
            "status": self.status.value if isinstance(self.status, AgentStatus) else str(self.status),
            "findings": self.findings,
            "evidence": self.evidence,
            "affected_files": self.affected_files,
            "line_numbers": self.line_numbers,
            "confidence": round(self.confidence, 2),
            "recommendation": self.recommendation,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "model_used": self.model_used,
            "handoff_to": self.handoff_to,
            "error": self.error,
            "data": self.data,
        }


class BaseAgent:
    """Base class for all SecureCode AI agents."""
    name: str = "BaseAgent"
    role: str = "Generic security agent"
    execution_mode: ExecutionMode = ExecutionMode.LOCAL_STATIC
    model_name: str = "deterministic"

    def is_available(self) -> bool:
        """Check whether the prerequisites for this agent are met."""
        return True

    def _execute_task(self, task: AgentTask) -> AgentResult:
        """Internal execution logic to be overridden by subclasses."""
        raise NotImplementedError

    def run(self, task: AgentTask) -> AgentResult:
        """Safe execution wrapper with automatic timing, state management and error capture."""
        start = time.perf_counter()
        if not self.is_available():
            return AgentResult(
                agent_name=self.name,
                task_id=task.task_id,
                execution_mode=self.execution_mode,
                status=AgentStatus.SKIPPED,
                error=f"Agent '{self.name}' is currently unavailable (missing server or credentials).",
                model_used=self.model_name,
                execution_time_ms=0.0,
            )

        try:
            result = self._execute_task(task)
            result.execution_time_ms = (time.perf_counter() - start) * 1000.0
            return result
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000.0
            return AgentResult(
                agent_name=self.name,
                task_id=task.task_id,
                execution_mode=self.execution_mode,
                status=AgentStatus.FAILED,
                error=str(exc),
                model_used=self.model_name,
                execution_time_ms=elapsed,
            )
