"""CTF / practice-lab training companion.

Helps you *learn* offensive-security methodology on intentionally-vulnerable
targets by giving structured checklists, an engagement notebook, and progress
tracking. It is a study aid and journal - it does not run any attacks.

Engagements are stored as JSON under ~/.outcats/labs/.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

LABS_DIR = Path.home() / ".outcats" / "labs"
_METHODS = Path(__file__).resolve().parent.parent / "data" / "methodologies.json"


@lru_cache(maxsize=1)
def _methodologies() -> dict:
    return json.loads(_METHODS.read_text())


def list_templates() -> dict[str, str]:
    tpls = _methodologies()["templates"]
    return {k: v["title"] for k, v in tpls.items()}


def get_template(name: str) -> dict:
    tpls = _methodologies()["templates"]
    if name not in tpls:
        raise KeyError(
            f"Unknown template '{name}'. Available: {', '.join(tpls)}"
        )
    return tpls[name]


@dataclass
class Note:
    at: float
    phase: str
    text: str


@dataclass
class Engagement:
    name: str
    template: str
    platform: str = "practice-lab"
    created_at: float = field(default_factory=time.time)
    completed_steps: list[str] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)

    # ---- persistence -----------------------------------------------------
    @property
    def _path(self) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.name)
        return LABS_DIR / f"{safe}.json"

    def save(self) -> Path:
        LABS_DIR.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(asdict(self), indent=2))
        return self._path

    @classmethod
    def load(cls, name: str) -> "Engagement":
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        path = LABS_DIR / f"{safe}.json"
        if not path.exists():
            raise FileNotFoundError(f"No engagement named '{name}'.")
        return cls(**json.loads(path.read_text()))

    # ---- behaviour -------------------------------------------------------
    def add_note(self, phase: str, text: str) -> None:
        self.notes.append(asdict(Note(at=time.time(), phase=phase, text=text)))

    def complete_step(self, step: str) -> None:
        if step not in self.completed_steps:
            self.completed_steps.append(step)

    def checklist(self) -> list[tuple[str, str, bool]]:
        """Return (phase, step, done) tuples for the engagement's template."""
        tpl = get_template(self.template)
        rows: list[tuple[str, str, bool]] = []
        for phase in tpl["phases"]:
            for step in phase["steps"]:
                rows.append((phase["name"], step, step in self.completed_steps))
        return rows

    def progress(self) -> tuple[int, int]:
        rows = self.checklist()
        done = sum(1 for _, _, d in rows if d)
        return done, len(rows)


def list_engagements() -> list[str]:
    if not LABS_DIR.exists():
        return []
    return sorted(p.stem for p in LABS_DIR.glob("*.json"))
