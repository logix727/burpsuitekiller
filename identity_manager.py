import json
import os
from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class Persona:
    name: str
    token: str
    user_id: str
    headers: dict = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.token:
            prefix = "Bearer " if not self.token.lower().startswith("bearer ") else ""
            self.headers['Authorization'] = f"{prefix}{self.token}"

class IdentityManager:
    def __init__(self, storage_file="identities.json"):
        self.storage_file = storage_file
        self.personas: List[Persona] = []
        self.load()

    def add_persona(self, name: str, token: str, user_id: str):
        # Update if exists
        for p in self.personas:
            if p.name == name:
                p.token = token
                p.user_id = user_id
                # Re-init headers
                p.__post_init__()
                self.save()
                return
        
        # Add new
        new_persona = Persona(name, token, user_id)
        self.personas.append(new_persona)
        self.save()

    def get_persona(self, name: str) -> Optional[Persona]:
        for p in self.personas:
            if p.name == name:
                return p
        return None

    def get_all(self) -> List[Persona]:
        return self.personas

    def delete_persona(self, name: str):
        self.personas = [p for p in self.personas if p.name != name]
        self.save()

    def save(self):
        data = [asdict(p) for p in self.personas]
        with open(self.storage_file, 'w') as f:
            json.dump(data, f, indent=4)

    def load(self):
        if not os.path.exists(self.storage_file):
            return
        try:
            with open(self.storage_file, 'r') as f:
                data = json.load(f)
                self.personas = [Persona(**d) for d in data]
        except Exception:
            self.personas = []
