from abc import ABC, abstractmethod
from ..core.config import Config
from ..core.input_parser import Target

class BaseModule(ABC):
    def __init__(self, config: Config):
        self.config = config
        self.name = "base"
        self.description = "Base module"

    @abstractmethod
    async def run(self, target: Target) -> dict:
        """
        Run the scan on the target.
        Returns a dictionary of results.
        """
        pass
