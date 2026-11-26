"""SecureCode AI Multi-Agent Architecture Package."""
from .base_agent import (
    BaseAgent,
    AgentTask,
    AgentResult,
    AgentStatus,
    ExecutionMode,
)
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
from .intelligent_task_router import IntelligentTaskRouter
from .master_orchestrator import MasterOrchestrator

__all__ = [
    "BaseAgent",
    "AgentTask",
    "AgentResult",
    "AgentStatus",
    "ExecutionMode",
    "FileScannerAgent",
    "SyntaxCheckerAgent",
    "PatternDetectionAgent",
    "DependencyAnalysisAgent",
    "ReportGenerationAgent",
    "VerificationAgent",
    "CodeExplanationAgent",
    "SimpleBugDetectionAgent",
    "BasicCodeRepairAgent",
    "DocumentationAgent",
    "ErrorClassificationAgent",
    "AdvancedVulnerabilityAnalysisAgent",
    "CrossFileDataFlowAgent",
    "ComplexRepairAgent",
    "SecurityInvestigationAgent",
    "AdvancedProjectUnderstandingAgent",
    "IntelligentTaskRouter",
    "MasterOrchestrator",
]
