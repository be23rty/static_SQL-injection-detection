"""Local AI Agents Powered by Ollama (Offline, e.g. Qwen 2.5 Coder 3B).

Provides 5 local intelligence agents:
1. CodeExplanationAgent
2. SimpleBugDetectionAgent
3. BasicCodeRepairAgent
4. DocumentationAgent
5. ErrorClassificationAgent
"""
from __future__ import annotations
import json
import os
from typing import Any, Dict, List

from .base_agent import BaseAgent, AgentTask, AgentResult, AgentStatus, ExecutionMode
import ollama_agent


def _get_ollama_model() -> str:
    return os.getenv("SECURECODE_OLLAMA_MODEL", "qwen2.5-coder:3b")


def _is_ollama_up() -> bool:
    try:
        status = ollama_agent.check_ollama()
        return bool(status.get("available"))
    except Exception:
        return False


class LocalOllamaBaseAgent(BaseAgent):
    execution_mode = ExecutionMode.LOCAL_AI

    @property
    def model_name(self) -> str:
        return _get_ollama_model()

    def is_available(self) -> bool:
        return _is_ollama_up()


class CodeExplanationAgent(LocalOllamaBaseAgent):
    """Explains architecture, control flow, and security implications of code."""
    name = "CodeExplanationAgent"
    role = "Local Code Logic & Security Explanation"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        prompt = (
            f"Explain the following {task.filename} code cleanly and concisely. "
            f"Highlight security-relevant logic, inputs, and functions:\n\n{task.code}"
        )
        messages = [
            {"role": "system", "content": "You are a secure code explainer. Return your answer as a JSON object with keys 'explanation' (string) and 'key_components' (array of strings)."},
            {"role": "user", "content": prompt}
        ]
        raw = ollama_agent._chat(messages, timeout=60)
        data = ollama_agent._extract_json(raw)
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            confidence=0.88,
            model_used=self.model_name,
            recommendation=data.get("explanation", ""),
            data=data,
        )


class SimpleBugDetectionAgent(LocalOllamaBaseAgent):
    """Detects simple bugs, null dereferences, and common anti-patterns locally."""
    name = "SimpleBugDetectionAgent"
    role = "Local Functional Bug & Anti-Pattern Detection"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        messages = [
            {
                "role": "system",
                "content": (
                    "Analyze the given code for simple logic bugs, off-by-one errors, unhandled null/None cases, "
                    "or broken assumptions. Return a JSON object with key 'bugs' (array of {line, description, severity})."
                )
            },
            {"role": "user", "content": f"File: {task.filename}\n\n{task.code}"}
        ]
        raw = ollama_agent._chat(messages, timeout=60)
        data = ollama_agent._extract_json(raw)
        bugs = data.get("bugs", [])
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            findings=bugs,
            confidence=0.85,
            model_used=self.model_name,
            recommendation=f"Found {len(bugs)} functional bug(s) locally.",
            data=data,
        )


class BasicCodeRepairAgent(LocalOllamaBaseAgent):
    """Generates basic local patches for common vulnerabilities."""
    name = "BasicCodeRepairAgent"
    role = "Local Security Patch Generation"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        findings = task.context.get("findings", [])
        res = ollama_agent.repair_code(task.code, task.filename, findings=findings)
        repaired_code = res.get("repaired_code", task.code)
        explanation = res.get("explanation", "Basic local repair applied.")
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED if repaired_code != task.code else AgentStatus.SKIPPED,
            confidence=0.85,
            model_used=self.model_name,
            evidence=repaired_code,
            recommendation=explanation,
            data=res,
            handoff_to="VerificationAgent",
        )


class DocumentationAgent(LocalOllamaBaseAgent):
    """Generates security documentation, remediation guides, and inline docstrings."""
    name = "DocumentationAgent"
    role = "Local Security Documentation & Mitigation Guide"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        messages = [
            {
                "role": "system",
                "content": "Generate security documentation and best practices for this module. Return JSON with 'docstring', 'security_considerations' (array), and 'mitigations' (array)."
            },
            {"role": "user", "content": f"File: {task.filename}\n\n{task.code}"}
        ]
        raw = ollama_agent._chat(messages, timeout=60)
        data = ollama_agent._extract_json(raw)
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            confidence=0.9,
            model_used=self.model_name,
            recommendation="Generated local security documentation.",
            data=data,
        )


class ErrorClassificationAgent(LocalOllamaBaseAgent):
    """Classifies error messages, exceptions, or security warnings into taxonomy."""
    name = "ErrorClassificationAgent"
    role = "Local Error & Security Taxonomy Classifier"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        error_text = task.context.get("error_text") or task.code
        messages = [
            {
                "role": "system",
                "content": "Classify this error or warning into CWE/OWASP categories. Return JSON with 'cwe_id', 'category', 'severity', and 'description'."
            },
            {"role": "user", "content": error_text}
        ]
        raw = ollama_agent._chat(messages, timeout=45)
        data = ollama_agent._extract_json(raw)
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            confidence=0.9,
            model_used=self.model_name,
            recommendation=f"Classified as {data.get('cwe_id', 'General')} - {data.get('category', 'Security')}.",
            data=data,
        )
