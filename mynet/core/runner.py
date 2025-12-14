import asyncio
import importlib
from typing import List
from .config import Config
from .input_parser import Target
from ..modules.base import BaseModule
from ..modules.dns_scanner import DNSScanner
from ..modules.port_scanner import PortScanner
from ..modules.http_scanner import HTTPScanner

class Runner:
    def __init__(self, config: Config):
        self.config = config
        self.modules: List[BaseModule] = self._load_modules()

    def _load_modules(self) -> List[BaseModule]:
        modules = []
        # Import standard modules
        # We can scan the directory, but for simplicity in this environment, 
        # let's just use importlib to import known modules or walk pkg.
        # To be robust and "plugin-like", walking is better.
        import pkgutil
        import importlib
        import mynet.modules
        
        # Iterate over all modules in mynet.modules package
        package = mynet.modules
        prefix = package.__name__ + "."
        
        for _, name, _ in pkgutil.iter_modules(package.__path__, prefix):
            if name.endswith("base"): continue
            try:
                mod = importlib.import_module(name)
                # Find BaseModule subclasses
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseModule) and attr is not BaseModule:
                        modules.append(attr(self.config))
            except Exception as e:
                print(f"Failed to load module {name}: {e}")
                
        return modules

    async def run_scan(self, targets: List[Target]):
        """
        Run all loaded modules against all targets.
        Returns a structured dictionary of results.
        """
        results = {}
        
        # We can run targets in parallel, and modules in parallel per target?
        # Or simplistic: For each target, run all modules concurrently.
        
        # Create a semaphore to limit concurrent target scans if we had many targets.
        # But for now let's just use gather.
        
        tasks = []
        for target in targets:
            tasks.append(self._scan_target(target))
            
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
