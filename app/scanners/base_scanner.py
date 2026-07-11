from abc import ABC, abstractmethod

class BaseScanner(ABC):
    
    @abstractmethod
    def scan(self, target: str) -> dict:
        """
        Execute the scan against the target.
        Returns a dictionary containing the results.
        """
        pass
