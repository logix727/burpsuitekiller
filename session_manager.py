import json
import dataclasses
from typing import List, Dict, Any
from engine import TestResult
from scanner import Vulnerability

class SessionManager:
    @staticmethod
    def serialize_obj(obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    def save_session(self, filepath: str, urls: List[str], scan_map: Dict[str, TestResult], risk_map: Dict[str, List[Vulnerability]], surface_map: Dict[str, List[str]] = None):
        data = {
            "version": "1.1",
            "urls": urls,
            "scan_map": {k: self.serialize_obj(v) for k, v in scan_map.items()},
            "risk_map": {k: [self.serialize_obj(v) for v in v_list] for k, v_list in risk_map.items()},
            "surface_map": surface_map or {}
        }
        
        import os
        tmp_path = filepath + ".tmp"
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=self.serialize_obj)
            
            # Atomic swap
            os.replace(tmp_path, filepath)
        except Exception as e:
            # Clean up temp if failed
            if os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except: pass
            raise e

    def load_session(self, filepath: str):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Reconstruct Objects
            urls = data.get("urls", [])
            
            # Reconstruct TestResults
            scan_map = {}
            for k, v in data.get("scan_map", {}).items():
                scan_map[k] = TestResult(**v)
            
            # Reconstruct Vulnerabilities
            risk_map = {}
            for k, v_list in data.get("risk_map", {}).items():
                risk_map[k] = [Vulnerability(**v) for v in v_list]
                
            surface_map = data.get("surface_map", {})
                
            return {
                "urls": urls,
                "scan_map": scan_map,
                "risk_map": risk_map,
                "surface_map": surface_map
            }
        except Exception as e:
            print(f"Failed to load session: {e}")
            return None
