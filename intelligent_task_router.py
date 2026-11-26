"""Intelligent Task Router for SecureCode AI.

Implements rule-based, mode-aware task routing:
- AUTO: Uses optimal agent based on task complexity (local for rules/syntax/files, online for deep reasoning)
- LOCAL_ONLY: Forces all tasks to run locally (Ollama + local non-LLM) without cloud APIs
- ONLINE_ONLY: Routes all AI tasks to online cloud models
- Fallback: Automatically falls back to local execution if online calls fail or credentials are missing.
"""
from __future__ import annotations
import os
from typing import Any, Dict, Optional, Tuple, Type

from .base_agent import BaseAgent, AgentTask, AgentResult, AgentStatus, ExecutionMode
from .local_non_llm_agents import (
    FileScannerAgent,
    SyntaxCheckerAgent,
    PatternDetectionAgent,
    DependencyAnalysisAgent,
    ReportGenerationAgent,
    VerificationAgent,
)
from .local_ollama_agents import (
    CodeExplanationAgent,
    SimpleBugDetectionAgent,
    BasicCodeRepairAgent,
    DocumentationAgent,
    ErrorClassificationAgent,
)
from .online_ai_agents import (
    AdvancedVulnerabilityAnalysisAgent,
    CrossFileDataFlowAgent,
    ComplexRepairAgent,
    SecurityInvestigationAgent,
    AdvancedProjectUnderstandingAgent,
)


ROUTING_TABLE: Dict[str, Dict[str, Type[BaseAgent]]] = {
    # task_type -> { primary, fallback }
    "scan_files": {
        "local": FileScannerAgent,
        "online": FileScannerAgent,
    },
    "syntax_check": {
        "local": SyntaxCheckerAgent,
        "online": SyntaxCheckerAgent,
    },
    "pattern_scan": {
        "local": PatternDetectionAgent,
        "online": PatternDetectionAgent,
    },
    "dependency_scan": {
        "local": DependencyAnalysisAgent,
        "online": DependencyAnalysisAgent,
    },
    "report_generate": {
        "local": ReportGenerationAgent,
        "online": ReportGenerationAgent,
    },
    "verify_repair": {
        "local": VerificationAgent,
        "online": VerificationAgent,
    },
    "explain": {
        "local": CodeExplanationAgent,
        "online": AdvancedProjectUnderstandingAgent,
    },
    "simple_bugs": {
        "local": SimpleBugDetectionAgent,
        "online": AdvancedVulnerabilityAnalysisAgent,
    },
    "documentation": {
        "local": DocumentationAgent,
        "online": AdvancedProjectUnderstandingAgent,
    },
    "error_classify": {
        "local": ErrorClassificationAgent,
        "online": SecurityInvestigationAgent,
    },
    "investigate": {
        "local": PatternDetectionAgent,  # Local fallback is static pattern reasoning
        "online": AdvancedVulnerabilityAnalysisAgent,
    },
    "cross_file_flow": {
        "local": PatternDetectionAgent,
        "online": CrossFileDataFlowAgent,
    },
    "repair": {
        "local": BasicCodeRepairAgent,
        "online": ComplexRepairAgent,
    },
    "security_investigation": {
        "local": PatternDetectionAgent,
        "online": SecurityInvestigationAgent,
    },
    "project_understanding": {
        "local": FileScannerAgent,
        "online": AdvancedProjectUnderstandingAgent,
    },
}


class IntelligentTaskRouter:
    """Routes incoming tasks to the optimal agent based on policy, user preference and availability."""

    def __init__(self, mode: str = "AUTO"):
        self.mode = mode.upper()  # 'AUTO', 'LOCAL_ONLY', 'ONLINE_ONLY'

    def get_routing_decision(self, task: AgentTask) -> Tuple[BaseAgent, Optional[BaseAgent], str]:
        """Determine primary agent, fallback agent, and reasoning explanation."""
        preferred_mode = task.preferred_mode.upper() if task.preferred_mode else self.mode
        effective_mode = preferred_mode if preferred_mode in ("LOCAL_ONLY", "ONLINE_ONLY") else self.mode

        task_type = task.task_type
        mapping = ROUTING_TABLE.get(task_type, {
            "local": PatternDetectionAgent,
            "online": AdvancedVulnerabilityAnalysisAgent,
        })

        local_agent_cls = mapping["local"]
        online_agent_cls = mapping.get("online", local_agent_cls)

        local_agent = local_agent_cls()
        online_agent = online_agent_cls()

        if effective_mode == "LOCAL_ONLY":
            reason = f"Mode is LOCAL_ONLY: Routed '{task_type}' to local agent {local_agent.name}."
            return local_agent, None, reason

        if effective_mode == "ONLINE_ONLY":
            if online_agent.is_available():
                reason = f"Mode is ONLINE_ONLY: Routed '{task_type}' to online agent {online_agent.name}."
                return online_agent, local_agent, reason
            else:
                reason = f"Mode is ONLINE_ONLY but online credentials missing. Falling back to local agent {local_agent.name}."
                return local_agent, None, reason

        # AUTO mode: Decide based on task nature
        # 1. Non-LLM tasks always execute locally
        if task_type in ("scan_files", "syntax_check", "pattern_scan", "dependency_scan", "report_generate", "verify_repair"):
            reason = f"AUTO routing: Deterministic task '{task_type}' executed locally via {local_agent.name} (zero API cost)."
            return local_agent, None, reason

        # 2. Complex tasks prefer online if available, with local fallback
        if task_type in ("investigate", "cross_file_flow", "repair", "security_investigation", "project_understanding"):
            if online_agent.is_available():
                reason = f"AUTO routing: Complex task '{task_type}' routed to cloud AI {online_agent.name} ({online_agent.model_name}) with local fallback."
                return online_agent, local_agent, reason
            else:
                reason = f"AUTO routing: Cloud AI unavailable for '{task_type}'. Safely falling back to local agent {local_agent.name}."
                return local_agent, None, reason

        # 3. Simple AI tasks prefer local Ollama if running, else online
        if local_agent.is_available():
            reason = f"AUTO routing: Task '{task_type}' routed to local Ollama {local_agent.name} ({local_agent.model_name})."
            return local_agent, online_agent if online_agent.is_available() else None, reason
        elif online_agent.is_available():
            reason = f"AUTO routing: Local Ollama inactive. Escalating '{task_type}' to cloud AI {online_agent.name}."
            return online_agent, None, reason
        else:
            reason = f"AUTO routing: Both local Ollama and cloud AI unavailable. Running deterministic fallback {PatternDetectionAgent.name}."
            return PatternDetectionAgent(), None, reason

    def route_and_execute(self, task: AgentTask) -> AgentResult:
        """Route the task, execute it on the chosen agent, and apply fallback if needed."""
        primary_agent, fallback_agent, reason = self.get_routing_decision(task)

        result = primary_agent.run(task)
        result.data["routing_reason"] = reason
        result.data["primary_agent"] = primary_agent.name

        # If primary failed and fallback exists, trigger fallback
        if result.status == AgentStatus.FAILED and fallback_agent and fallback_agent.is_available():
            fallback_res = fallback_agent.run(task)
            fallback_res.data["routing_reason"] = f"Primary agent '{primary_agent.name}' failed. Fallback executed on '{fallback_agent.name}'."
            fallback_res.data["fallback_triggered"] = True
            fallback_res.data["primary_error"] = result.error
            return fallback_res

        return result
