from abc import ABC, abstractmethod
from typing import Dict, Any
from app.scanners.config import ScanConfig

class BaseModule(ABC):
    """
    Abstract base class for all Website Scanner recon and evaluation modules.
    """
    name: str = "BaseModule"

    @abstractmethod
    def run(self, context: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
        """
        Execute module analysis against shared context and configuration.
        Returns a dictionary of result updates to merge into context.
        """
        pass
