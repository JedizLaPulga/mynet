import asyncio
import importlib
import logging
import pkgutil
from typing import List, Dict, Any, Optional, Set, Iterator, Tuple, Type
from .config import Config
from .input_parser import Target
from ..modules.base import BaseModule
import mynet.modules

logger = logging.getLogger(__name__)


class Runner:
    def __init__(
        self,
        config: Config,
        include_modules: Optional[List[str]] = None,
        exclude_modules: Optional[List[str]] = None,
    ):
        self.config = config
        self.include_modules = self._normalize_names(include_modules)
        self.exclude_modules = self._normalize_names(exclude_modules)
        self.modules: List[BaseModule] = self._load_modules()

    def _normalize_names(self, names: Optional[List[str]]) -> Set[str]:
        """Normalize module names to lowercase for case-insensitive matching."""
        if not names:
            return set()
        return {name.lower().strip() for name in names}

    def _should_load_module(self, module_name: str) -> bool:
        """Check if a module should be loaded based on include/exclude filters."""
        name_lower = module_name.lower()
        
        # If include list is specified, module must be in it
        if self.include_modules:
            return name_lower in self.include_modules
        
        # If exclude list is specified, module must not be in it
        if self.exclude_modules:
            return name_lower not in self.exclude_modules
        
        # No filters, load all
        return True

    @staticmethod
    def _discover_module_classes() -> Iterator[Tuple[str, Type[BaseModule]]]:
        """
        Discover all BaseModule subclasses in mynet.modules package.
        Yields (module_file_name, class) tuples.
        """
        package = mynet.modules
        prefix = package.__name__ + "."

        if not hasattr(package, "__path__"):
            return

        for _, name, _ in pkgutil.iter_modules(package.__path__, prefix):
            if name.endswith("base"):
                continue
            try:
                mod = importlib.import_module(name)
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule
                    ):
                        yield name, attr
            except Exception as e:
                logger.warning("Failed to import module %s: %s", name, e)

    def _load_modules(self) -> List[BaseModule]:
        """Load and instantiate all scanner modules, applying filters."""
        modules = []

        for module_name, cls in self._discover_module_classes():
            try:
                instance = cls(self.config)
                if self._should_load_module(instance.name):
                    modules.append(instance)
            except Exception as e:
                logger.error("Failed to instantiate %s: %s", cls.__name__, e)

        return modules

    @staticmethod
    def list_available_modules() -> List[Dict[str, str]]:
        """
        List all available scanner modules via class introspection.
        Returns list of dicts with 'name', 'description', and 'class'.
        """
        modules_info = []
        temp_config = Config()

        for _, cls in Runner._discover_module_classes():
            try:
                instance = cls(temp_config)
                modules_info.append({
                    "name": instance.name,
                    "description": instance.description,
                    "class": cls.__name__,
                })
            except Exception as e:
                logger.warning("Could not introspect %s: %s", cls.__name__, e)

        return sorted(modules_info, key=lambda x: x["name"])

    def get_loaded_module_names(self) -> List[str]:
        """Return list of currently loaded module names."""
        return [mod.name for mod in self.modules]

    async def run_scan(self, targets: List[Target]):
        """
        Run all loaded modules against all targets.
        Returns a structured dictionary of results.
        """
        results = {}
        
        # We can run targets in parallel
        tasks = []
        # Implement concurrency control with Semaphore
        sem = asyncio.Semaphore(self.config.concurrency)

        async def _bounded_scan(t):
            async with sem:
                return await self._scan_target(t)

        for target in targets:
            tasks.append(_bounded_scan(target))
            
        target_results = await asyncio.gather(*tasks)
        
        for tr in target_results:
            # tr is (target_obj, module_results_dict)
            t_obj, mod_res = tr
            # Use original input as key or host?
            key = t_obj.host if t_obj.host else t_obj.original_input
            results[key] = {
                "target": t_obj.__dict__,
                "scans": mod_res
            }
            
        return results

    async def _scan_target(self, target: Target):
        # Run all modules for this target
        module_tasks = []
        for mod in self.modules:
            module_tasks.append(self._run_module_safe(mod, target))
            
        # Wait for all modules to finish for this target
        mod_results_list = await asyncio.gather(*module_tasks)
        
        mod_results = {}
        for res in mod_results_list:
            mod_results.update(res)
            
        return target, mod_results

    async def _run_module_safe(self, module: BaseModule, target: Target):
        try:
            data = await module.run(target)
            return {module.name: data}
        except Exception as e:
            return {module.name: {"error": str(e), "status": "crashed"}}
