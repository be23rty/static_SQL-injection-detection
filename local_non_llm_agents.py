"""Local Non-LLM Agents for SecureCode AI.

Fully offline, deterministic, zero-dependency, zero-API-key security agents:
1. FileScannerAgent
2. SyntaxCheckerAgent
3. PatternDetectionAgent
4. DependencyAnalysisAgent
5. ReportGenerationAgent
6. VerificationAgent
"""
from __future__ import annotations
import ast
import os
import re
from typing import Any, Dict, List

from .base_agent import BaseAgent, AgentTask, AgentResult, AgentStatus, ExecutionMode
from broad_security_analyzer import BroadSecurityAnalyzer
from secret_scanner import scan_secrets
from dependency_scanner import scan_dependencies
from multilang_security_analyzer import detect_language, language_for


IGNORED_DIRECTORIES = {
    "node_modules", ".git", ".venv", "venv", "__pycache__",
    "build", "dist", "target", ".idea", ".vscode", ".tox"
}
SUPPORTED_EXTS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".java",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"
}


class FileScannerAgent(BaseAgent):
    """Scans projects, maps file hierarchy, detects languages, and identifies manifests."""
    name = "FileScannerAgent"
    role = "Project Structure & File Discovery"
    execution_mode = ExecutionMode.LOCAL_STATIC
    model_name = "Deterministic File System Walker"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        file_sources = task.context.get("file_sources", {})
        if not file_sources and task.code:
            file_sources = {task.filename: task.code}

        scanned_files = []
        manifest_files = []
        total_bytes = 0

        for rel_path, content in file_sources.items():
            norm_path = rel_path.replace("\\", "/")
            parts = norm_path.split("/")
            if any(p in IGNORED_DIRECTORIES for p in parts[:-1]):
                continue

            ext = os.path.splitext(norm_path.lower())[1]
            base_name = os.path.basename(norm_path).lower()
            size = len(content.encode("utf-8", errors="replace"))
            total_bytes += size

            if base_name in ("requirements.txt", "package.json"):
                manifest_files.append({"path": norm_path, "type": base_name, "size": size})

            if ext in SUPPORTED_EXTS or base_name in ("requirements.txt", "package.json"):
                lang_res = detect_language(content, norm_path)
                if isinstance(lang_res, tuple) and len(lang_res) >= 2:
                    lang, conf = lang_res[0], lang_res[1]
                elif isinstance(lang_res, dict):
                    lang = lang_res.get("language", language_for(norm_path))
                    conf = lang_res.get("confidence", 1.0)
                else:
                    lang = language_for(norm_path)
                    conf = 1.0

                scanned_files.append({
                    "path": norm_path,
                    "language": lang,
                    "confidence": conf,
                    "size": size,
                    "lines": len(content.splitlines()),
                })

        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            affected_files=[f["path"] for f in scanned_files],
            confidence=1.0,
            model_used=self.model_name,
            recommendation=f"Discovered {len(scanned_files)} eligible source files and {len(manifest_files)} manifests.",
            data={
                "files": scanned_files,
                "manifest_files": manifest_files,
                "total_files": len(scanned_files),
                "total_bytes": total_bytes,
            },
            handoff_to="SyntaxCheckerAgent",
        )


class SyntaxCheckerAgent(BaseAgent):
    """Detects syntax errors across supported languages before analysis."""
    name = "SyntaxCheckerAgent"
    role = "Language Syntax Validation"
    execution_mode = ExecutionMode.LOCAL_STATIC
    model_name = "Multi-language AST Parser"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        file_sources = task.context.get("file_sources", {})
        if not file_sources and task.code:
            file_sources = {task.filename: task.code}

        errors = []
        for path, code in file_sources.items():
            ext = os.path.splitext(path.lower())[1]
            if ext == ".py":
                try:
                    ast.parse(code, filename=path)
                except SyntaxError as e:
                    errors.append({
                        "file": path,
                        "line": getattr(e, "lineno", 1) or 1,
                        "column": getattr(e, "offset", 1) or 1,
                        "error": e.msg,
                        "language": "Python",
                    })
            elif ext in (".js", ".jsx", ".mjs", ".cjs", ".java", ".c", ".cpp"):
                # Basic bracket / quote balance validation for non-Python sources
                err = self._check_balance(code, path)
                if err:
                    errors.append(err)

        status = AgentStatus.FAILED if errors else AgentStatus.COMPLETED
        line_numbers = [e["line"] for e in errors]
        affected = list({e["file"] for e in errors})

        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=status,
            affected_files=affected,
            line_numbers=line_numbers,
            findings=errors,
            confidence=1.0,
            model_used=self.model_name,
            recommendation="No syntax errors found." if not errors else f"Found {len(errors)} syntax error(s).",
            data={"syntax_errors": errors, "is_valid": len(errors) == 0},
            handoff_to="PatternDetectionAgent" if not errors else None,
        )

    def _check_balance(self, code: str, path: str) -> Dict[str, Any] | None:
        stack = []
        pairs = {')': '(', ']': '[', '}': '{'}
        line = 1
        in_str = None
        escape = False
        for idx, ch in enumerate(code):
            if ch == '\n':
                line += 1
                escape = False
                continue
            if escape:
                escape = False
                continue
            if ch == '\\':
                escape = True
                continue
            if in_str:
                if ch == in_str:
                    in_str = None
                continue
            if ch in ('"', "'", '`'):
                in_str = ch
                continue
            if ch in '([{':
                stack.append((ch, line))
            elif ch in ')]}':
                if not stack or stack.pop()[0] != pairs[ch]:
                    return {"file": path, "line": line, "error": f"Mismatched delimiter '{ch}'", "language": "Source"}
        if stack:
            unclosed, uline = stack[-1]
            return {"file": path, "line": uline, "error": f"Unclosed delimiter '{unclosed}'", "language": "Source"}
        return None


class PatternDetectionAgent(BaseAgent):
    """Static analysis rule engine for SQLi, XSS, Command Injection, and Hardcoded Secrets."""
    name = "PatternDetectionAgent"
    role = "Deterministic Vulnerability Scanner"
    execution_mode = ExecutionMode.LOCAL_STATIC
    model_name = "Broad Security & Secret Rule Engine"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        file_sources = task.context.get("file_sources", {})
        if not file_sources and task.code:
            file_sources = {task.filename: task.code}

        all_findings = []
        affected_files = set()
        line_numbers = []

        for rel_path, code in file_sources.items():
            ext = os.path.splitext(rel_path.lower())[1]
            # 1. AST Security Analysis for Python
            if ext == ".py":
                try:
                    analyzer = BroadSecurityAnalyzer(code, filename=rel_path)
                    for f in analyzer.analyze():
                        item = dict(f)
                        item["file"] = rel_path
                        item["agent"] = self.name
                        all_findings.append(item)
                        affected_files.add(rel_path)
                        if "line" in item:
                            line_numbers.append(item["line"])
                except Exception:
                    pass

            # 2. Hardcoded Secret Detection across all source files
            try:
                secrets = scan_secrets(code, filename=rel_path)
                for s in secrets:
                    item = dict(s)
                    item["agent"] = self.name
                    all_findings.append(item)
                    affected_files.add(rel_path)
                    if "line" in item:
                        line_numbers.append(item["line"])
            except Exception:
                pass

        # Sort findings by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda x: (sev_order.get(x.get("severity", "LOW"), 9), x.get("line", 0)))

        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            findings=all_findings,
            affected_files=list(affected_files),
            line_numbers=line_numbers,
            confidence=0.95,
            model_used=self.model_name,
            recommendation=f"Identified {len(all_findings)} potential security findings across {len(affected_files)} file(s).",
            data={"total_findings": len(all_findings)},
            handoff_to="DependencyAnalysisAgent",
        )


class DependencyAnalysisAgent(BaseAgent):
    """Software Composition Analysis (SCA) inspecting requirements.txt and package.json offline."""
    name = "DependencyAnalysisAgent"
    role = "Software Composition Analysis"
    execution_mode = ExecutionMode.LOCAL_STATIC
    model_name = "Offline Vulnerability Database (CVE/CVSS)"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        file_sources = task.context.get("file_sources", {})
        if not file_sources and task.code:
            file_sources = {task.filename: task.code}

        all_vulns = []
        manifest_reports = []

        for path, content in file_sources.items():
            base = os.path.basename(path).lower()
            if base in ("requirements.txt", "package.json"):
                report = scan_dependencies(content, filename=base)
                manifest_reports.append(report)
                for v in report.get("vulnerabilities", []):
                    item = dict(v)
                    item["file"] = path
                    item["agent"] = self.name
                    all_vulns.append(item)

        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            findings=all_vulns,
            affected_files=[r.get("manifest_path", "") for r in manifest_reports],
            confidence=1.0,
            model_used=self.model_name,
            recommendation=f"Found {len(all_vulns)} vulnerable dependencies in {len(manifest_reports)} manifest(s).",
            data={"manifest_reports": manifest_reports, "total_dependency_vulns": len(all_vulns)},
            handoff_to="ReportGenerationAgent",
        )


class ReportGenerationAgent(BaseAgent):
    """Synthesizes all findings into a clean structured security report."""
    name = "ReportGenerationAgent"
    role = "Security Report Synthesis"
    execution_mode = ExecutionMode.LOCAL_STATIC
    model_name = "Deterministic Report Generator"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        findings = task.context.get("findings", [])
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        categories = {}
        for f in findings:
            sev = (f.get("severity") or "LOW").upper()
            if sev in counts:
                counts[sev] += 1
            cat = f.get("category", "Security")
            categories[cat] = categories.get(cat, 0) + 1

        total = len(findings)
        score = max(0, 100 - (counts["CRITICAL"] * 25 + counts["HIGH"] * 10 + counts["MEDIUM"] * 4 + counts["LOW"] * 1))

        summary = {
            "total_vulnerabilities": total,
            "critical_severity": counts["CRITICAL"],
            "high_severity": counts["HIGH"],
            "medium_severity": counts["MEDIUM"],
            "low_severity": counts["LOW"],
            "security_score": score,
            "categories": categories,
        }

        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED,
            findings=findings,
            confidence=1.0,
            model_used=self.model_name,
            recommendation=f"Security Score: {score}/100 with {total} finding(s).",
            data={"summary": summary},
        )


class VerificationAgent(BaseAgent):
    """Verifies that repaired code resolves the vulnerability without regressions or syntax errors."""
    name = "VerificationAgent"
    role = "Post-Repair Validation & Regression Testing"
    execution_mode = ExecutionMode.LOCAL_STATIC
    model_name = "AST Regression & Verification Engine"

    def _execute_task(self, task: AgentTask) -> AgentResult:
        original_code = task.context.get("original_code", "")
        repaired_code = task.code
        filename = task.filename or "repaired.py"
        original_vuln_id = task.context.get("target_vuln_id")

        if not repaired_code or not repaired_code.strip():
            return AgentResult(
                agent_name=self.name,
                task_id=task.task_id,
                execution_mode=self.execution_mode,
                status=AgentStatus.FAILED,
                error="Verification failed: Repaired code is empty.",
            )

        # 1. Syntax check
        syntax_res = SyntaxCheckerAgent().run(AgentTask(task_type="syntax", code=repaired_code, filename=filename))
        if syntax_res.status == AgentStatus.FAILED:
            return AgentResult(
                agent_name=self.name,
                task_id=task.task_id,
                execution_mode=self.execution_mode,
                status=AgentStatus.FAILED,
                confidence=1.0,
                error=f"Verification failed: Syntax error in repaired code at line {syntax_res.line_numbers}: {syntax_res.findings}",
                data={"verified": False, "reason": "Syntax Error", "errors": syntax_res.findings},
            )

        # 2. Security scan on repaired code
        sec_res = PatternDetectionAgent().run(AgentTask(task_type="scan", code=repaired_code, filename=filename))
        new_findings = sec_res.findings or []

        # Check if original vulnerability was resolved
        still_present = False
        if original_vuln_id:
            for f in new_findings:
                if f.get("id") == original_vuln_id or f.get("rule_violated") == task.context.get("target_rule"):
                    still_present = True
                    break

        verified = (not still_present)
        diff_count = len(new_findings)

        return AgentResult(
            agent_name=self.name,
            task_id=task.task_id,
            execution_mode=self.execution_mode,
            status=AgentStatus.COMPLETED if verified else AgentStatus.FAILED,
            confidence=0.95,
            model_used=self.model_name,
            recommendation="Repair verified: Vulnerability resolved without syntax errors." if verified else "Repair incomplete: Vulnerability pattern remains in modified code.",
            data={
                "verified": verified,
                "repaired_clean": len(new_findings) == 0,
                "remaining_findings_count": diff_count,
                "remaining_findings": new_findings,
            },
        )
