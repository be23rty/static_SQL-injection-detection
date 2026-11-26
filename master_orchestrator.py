"""Master Orchestrator Agent for SecureCode AI.

Coordinates multi-agent workflows, self-healing pipelines,
concurrency, result aggregation, and activity logging.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from .base_agent import AgentTask, AgentResult, AgentStatus, ExecutionMode
from .intelligent_task_router import IntelligentTaskRouter
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


class MasterOrchestrator:
    """Central orchestrator managing all local and online agents."""

    _instance: Optional[MasterOrchestrator] = None

    @classmethod
    def get_instance(cls) -> MasterOrchestrator:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self, routing_mode: str = "AUTO"):
        self.router = IntelligentTaskRouter(mode=routing_mode)
        self.activity_logs: List[Dict[str, Any]] = []
        self.registered_agents = {
            # Local Non-LLM
            "FileScannerAgent": FileScannerAgent(),
            "SyntaxCheckerAgent": SyntaxCheckerAgent(),
            "PatternDetectionAgent": PatternDetectionAgent(),
            "DependencyAnalysisAgent": DependencyAnalysisAgent(),
            "ReportGenerationAgent": ReportGenerationAgent(),
            "VerificationAgent": VerificationAgent(),
            # Local Ollama
            "CodeExplanationAgent": CodeExplanationAgent(),
            "SimpleBugDetectionAgent": SimpleBugDetectionAgent(),
            "BasicCodeRepairAgent": BasicCodeRepairAgent(),
            "DocumentationAgent": DocumentationAgent(),
            "ErrorClassificationAgent": ErrorClassificationAgent(),
            # Online AI
            "AdvancedVulnerabilityAnalysisAgent": AdvancedVulnerabilityAnalysisAgent(),
            "CrossFileDataFlowAgent": CrossFileDataFlowAgent(),
            "ComplexRepairAgent": ComplexRepairAgent(),
            "SecurityInvestigationAgent": SecurityInvestigationAgent(),
            "AdvancedProjectUnderstandingAgent": AdvancedProjectUnderstandingAgent(),
        }

    def set_routing_mode(self, mode: str) -> None:
        self.router.mode = mode.upper()

    def get_agent_status_list(self) -> List[Dict[str, Any]]:
        """Return the list of all registered agents and their live availability."""
        agents = []
        for name, agent in self.registered_agents.items():
            agents.append({
                "name": agent.name,
                "role": agent.role,
                "execution_mode": agent.execution_mode.value,
                "model_name": agent.model_name,
                "available": agent.is_available(),
            })
        return agents

    def log_activity(
        self,
        agent_name: str,
        task_type: str,
        mode: str,
        status: str,
        execution_time_ms: float,
        model: str,
        findings_count: int = 0,
        handoff: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append an entry to the live Agent Activity log."""
        entry = {
            "id": f"act-{uuid.uuid4().hex[:8]}",
            "timestamp": time.strftime("%H:%M:%S"),
            "agent_name": agent_name,
            "task_type": task_type,
            "execution_mode": mode,
            "status": status,
            "execution_time_ms": round(execution_time_ms, 2),
            "model_used": model,
            "findings_count": findings_count,
            "handoff_to": handoff,
            "details": details or {},
        }
        self.activity_logs.insert(0, entry)
        if len(self.activity_logs) > 200:
            self.activity_logs.pop()

    def execute_task(self, task_type: str, code: str = "", filename: str = "source.py", context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Route and execute a single agent task with live logging."""
        task = AgentTask(
            task_type=task_type,
            code=code,
            filename=filename,
            context=context or {},
            preferred_mode=self.router.mode,
        )
        res = self.router.route_and_execute(task)
        self.log_activity(
            agent_name=res.agent_name,
            task_type=task_type,
            mode=res.execution_mode.value if isinstance(res.execution_mode, ExecutionMode) else str(res.execution_mode),
            status=res.status.value if isinstance(res.status, AgentStatus) else str(res.status),
            execution_time_ms=res.execution_time_ms,
            model=res.model_used,
            findings_count=len(res.findings),
            handoff=res.handoff_to,
            details=res.data,
        )
        return res

    def run_full_project_analysis(self, file_sources: Dict[str, str], project_title: str = "PROJECT") -> Dict[str, Any]:
        """Orchestrate the full multi-agent analysis pipeline across a project."""
        start_time = time.perf_counter()

        # Step 1: FileScannerAgent
        scan_res = self.execute_task("scan_files", filename=project_title, context={"file_sources": file_sources})

        # Step 2: Concurrently run SyntaxChecker, PatternDetection, and DependencyAnalysis
        context = {"file_sources": file_sources}
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_syntax = executor.submit(self.execute_task, "syntax_check", "", project_title, context)
            future_pattern = executor.submit(self.execute_task, "pattern_scan", "", project_title, context)
            future_dep = executor.submit(self.execute_task, "dependency_scan", "", project_title, context)

            syntax_res = future_syntax.result()
            pattern_res = future_pattern.result()
            dep_res = future_dep.result()

        all_findings = list(pattern_res.findings) + list(dep_res.findings)

        # Step 3: Cross-File Data Flow Analysis (if multiple files exist)
        cross_findings = []
        if len(file_sources) > 1:
            flow_res = self.execute_task("cross_file_flow", "", project_title, context)
            if flow_res.status == AgentStatus.COMPLETED:
                cross_findings = flow_res.findings
                all_findings.extend(cross_findings)

        # Step 4: Security Investigation / Triage on High/Critical findings
        high_critical = [f for f in all_findings if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
        if high_critical and self.router.mode != "LOCAL_ONLY":
            triage_res = self.execute_task("security_investigation", "", project_title, context={"findings": high_critical, "file_sources": file_sources})
            # Triage updates findings confidence

        # Step 5: Report Synthesis
        report_res = self.execute_task("report_generate", context={"findings": all_findings})
        total_time_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "success": True,
            "project": True,
            "filename": project_title,
            "total_files": len(file_sources),
            "vulnerabilities": all_findings,
            "syntax_errors": syntax_res.findings,
            "summary": report_res.data.get("summary", {}),
            "orchestration_time_ms": round(total_time_ms, 2),
            "routing_mode": self.router.mode,
            "activity_snapshot": self.activity_logs[:10],
        }

    def run_self_healing_pipeline(self, code: str, filename: str, target_vuln: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the full 11-step Self-Healing Pipeline (Section 8)."""
        start = time.perf_counter()
        # 1-4. Initial analysis
        pattern_res = self.execute_task("pattern_scan", code=code, filename=filename)
        findings = pattern_res.findings

        if not findings and not target_vuln:
            return {
                "success": True,
                "repaired": False,
                "message": "No vulnerabilities to repair.",
                "original_code": code,
                "repaired_code": code,
            }

        target_vuln_id = target_vuln.get("id") if target_vuln else (findings[0].get("id") if findings else None)

        # 5. Deep Investigation
        investigate_res = self.execute_task("investigate", code=code, filename=filename, context={"findings": findings})

        # 6-7. Generate Repair Suggestion & Diff
        repair_res = self.execute_task("repair", code=code, filename=filename, context={"findings": findings, "investigation": investigate_res.data})
        repaired_code = repair_res.evidence or code

        # 8-10. Run Verification on the repaired code
        verify_task = AgentTask(
            task_type="verify_repair",
            code=repaired_code,
            filename=filename,
            context={"original_code": code, "target_vuln_id": target_vuln_id},
        )
        verify_res = self.execute_task("verify_repair", code=repaired_code, filename=filename, context={"original_code": code, "target_vuln_id": target_vuln_id})

        elapsed = (time.perf_counter() - start) * 1000.0
        return {
            "success": True,
            "task_id": repair_res.task_id,
            "filename": filename,
            "original_code": code,
            "repaired_code": repaired_code,
            "repair_explanation": repair_res.recommendation,
            "verified": verify_res.data.get("verified", False),
            "repaired_clean": verify_res.data.get("repaired_clean", False),
            "remaining_findings_count": verify_res.data.get("remaining_findings_count", 0),
            "verification_status": verify_res.status.value,
            "execution_time_ms": round(elapsed, 2),
            "activity_snapshot": self.activity_logs[:5],
        }
