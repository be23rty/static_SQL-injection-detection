"""Online Cloud AI Agents Powered by Groq / Gemini / xAI.

Provides 5 advanced online security agents:
1. AdvancedVulnerabilityAnalysisAgent
2. CrossFileDataFlowAgent
3. ComplexRepairAgent
4. SecurityInvestigationAgent
5. AdvancedProjectUnderstandingAgent
"""
from __future__ import annotations
import os
from typing import Any, Dict, List

from .base_agent import BaseAgent, AgentTask, AgentResult, AgentStatus, ExecutionMode
import groq_agent
from project_graph import analyze_project_graph


def _get_online_model() -> str:
    groq_agent._load_env_file()
    return os.getenv("GROQ_MODEL", os.getenv("GEMINI_MODEL", groq_agent.DEFAULT_MODEL))


def _has_online_key() -> bool:
    try:
        key = groq_agent._get_raw_key()
        return bool(key and len(key.strip()) > 5)
    except Exception:
        return False


class OnlineBaseAgent(BaseAgent):
    execution_mode = ExecutionMode.ONLINE_AI

    @property
    def model_name(self) -> str:
        return _get_online_model()

    def is_available(self) -> bool:
        return _has_online_key()


class AdvancedVulnerabilityAnalysisAgent(OnlineBaseAgent):
    """Deep reasoning over complex vulnerability patterns, exploitability, and context."""
    name = "AdvancedVulnerabilityAnalysisAgent"
    role = "Deep Vulnerability Reasoning & Exploitability Analysis"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        findings = task.context.get("findings", [])
        graph_context = task.context.get("project_graph", {})
        res = groq_agent.investigate(
            code=task.code,
            filename=task.filename,
            findings=findings,
            graph_context=graph_context,
        )
        investigated_findings = res.get("findings", [])
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            findings=investigated_findings,
            confidence=0.92,
            model_used=self.model_name,
            recommendation=res.get("summary", "Online security analysis completed."),
            data=res,
            handoff_to="ComplexRepairAgent",
        )


class CrossFileDataFlowAgent(OnlineBaseAgent):
    """Traces data flow, variables, imports, and taint across multiple project files."""
    name = "CrossFileDataFlowAgent"
    role = "Cross-File Taint & Architecture Data Flow Analysis"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        file_sources = task.context.get("file_sources", {})
        if not file_sources and task.code:
            file_sources = {task.filename: task.code}

        # 1. Deterministic project call graph
        project_graph = analyze_project_graph(file_sources)

        # 2. Online cross-file data flow reasoning if multiple files exist
        prompt = (
            f"Trace user-controlled inputs, imports, and cross-file data flows across the following files.\n"
            f"Project Graph Hints: {project_graph}\n\n"
            f"Identify if input in one file flows unsafely into a database, command, or file sink in another file."
        )
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a Cross-File Data Flow Security Agent. "
                    "Analyze cross-file tainted data paths. Return JSON with 'cross_file_flows' (array of "
                    "{source_file, source_line, sink_file, sink_line, variable, vulnerability, severity}) and 'summary' (string)."
                )
            },
            {"role": "user", "content": prompt[:15000]}  # Context bounded
        ]

        raw = groq_agent._chat(messages, timeout=90)
        data = groq_agent._extract_json(raw)
        flows = data.get("cross_file_flows", [])

        # Format flows as standard findings
        findings = []
        affected = set()
        for flow in flows:
            affected.add(flow.get("source_file", task.filename))
            affected.add(flow.get("sink_file", task.filename))
            findings.append({
                "id": f"FLOW-{len(findings)+1:03d}",
                "category": "Cross-File Data Flow",
                "severity": flow.get("severity", "HIGH"),
                "file": flow.get("sink_file", task.filename),
                "line": flow.get("sink_line", 1),
                "title": f"Cross-file {flow.get('vulnerability', 'Taint Flow')} ({flow.get('source_file')} -> {flow.get('sink_file')})",
                "description": f"Variable '{flow.get('variable')}' flows from {flow.get('source_file')}:{flow.get('source_line')} into sensitive sink at {flow.get('sink_file')}:{flow.get('sink_line')}.",
                "agent": self.name,
                "confidence": 0.88,
            })

        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            findings=findings,
            affected_files=list(affected),
            confidence=0.88,
            model_used=self.model_name,
            recommendation=data.get("summary", f"Identified {len(findings)} cross-file data flow vulnerability paths."),
            data={"project_graph": project_graph, "flows": flows},
            handoff_to="SecurityInvestigationAgent",
        )


class ComplexRepairAgent(OnlineBaseAgent):
    """Context-aware secure patch generation with functional preservation and diff explanations."""
    name = "ComplexRepairAgent"
    role = "Intelligent Context-Aware Patch Generation"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        findings = task.context.get("findings", [])
        res = groq_agent.repair_code(
            code=task.code,
            filename=task.filename,
            findings=findings,
        )
        repaired = res.get("repaired_code", task.code)
        explanation = res.get("explanation", "Complex context-aware repair generated.")
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED if repaired != task.code else AgentStatus.SKIPPED,
            evidence=repaired,
            confidence=0.92,
            model_used=self.model_name,
            recommendation=explanation,
            data=res,
            handoff_to="VerificationAgent",
        )


class SecurityInvestigationAgent(OnlineBaseAgent):
    """Correlates evidence across files, rejects false positives, and identifies root causes."""
    name = "SecurityInvestigationAgent"
    role = "Evidence Correlation & False-Positive Elimination"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        findings = task.context.get("findings", [])
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a Security Investigation Agent. Review findings for false positives, ambient sanitizers, "
                    "or framework protection. Return JSON with 'confirmed_findings' (array), 'dismissed_findings' (array of {id, reason}), "
                    "and 'root_cause_analysis' (string)."
                )
            },
            {"role": "user", "content": f"File: {task.filename}\nCode:\n{task.code[:10000]}\n\nFindings:\n{findings}"}
        ]
        raw = groq_agent._chat(messages, timeout=75)
        data = groq_agent._extract_json(raw)
        confirmed = data.get("confirmed_findings", findings)
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            findings=confirmed,
            confidence=0.95,
            model_used=self.model_name,
            recommendation=data.get("root_cause_analysis", "Evidence correlation completed."),
            data=data,
        )


class AdvancedProjectUnderstandingAgent(OnlineBaseAgent):
    """Analyzes full project architecture, entrypoints, and cross-module interactions."""
    name = "AdvancedProjectUnderstandingAgent"
    role = "Full Project Architecture Understanding"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        file_sources = task.context.get("file_sources", {})
        manifests = [p for p in file_sources if os.path.basename(p) in ("requirements.txt", "package.json")]
        sources_summary = "\n".join([f"- {p} ({len(c.splitlines())} lines)" for p, c in file_sources.items()])
        prompt = (
            f"Analyze the overall project architecture, attack surface, and security posture.\n"
            f"Files:\n{sources_summary}\n\nManifests: {manifests}"
        )
        messages = [
            {
                "role": "system",
                "content": "You are an Architecture Understanding Agent. Return JSON with 'architecture_type', 'attack_surface_areas' (array), 'entrypoints' (array), and 'key_recommendations' (array)."
            },
            {"role": "user", "content": prompt}
        ]
        raw = groq_agent._chat(messages, timeout=60)
        data = groq_agent._extract_json(raw)
        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            confidence=0.9,
            model_used=self.model_name,
            recommendation=f"Project Architecture: {data.get('architecture_type', 'Modular')}.",
            data=data,
        )
