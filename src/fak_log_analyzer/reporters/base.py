"""Base reporter interface."""

from abc import ABC, abstractmethod

from fak_log_analyzer.models import AnalysisResult, ReportConfig


class Reporter(ABC):
    """Base class for analysis result reporters."""

    @abstractmethod
    def render(
        self,
        result: AnalysisResult,
        config: ReportConfig,
    ) -> str:
        """Render an analysis result."""
        raise NotImplementedError
