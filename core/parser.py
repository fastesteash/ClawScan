"""
Parses OpenClaw skill packages from a directory.
Supports both claw.json and skill.yaml manifests alongside
instructions.md / SKILL.md content files.
"""

import json
import re
from pathlib import Path
from typing import Optional

import yaml


class SkillParseError(Exception):
    pass


class Skill:
    def __init__(self, path: Path):
        self.path = path
        self.name: str = path.name
        self.manifest: dict = {}
        self.manifest_format: str = ""
        self.instructions: str = ""
        self.readme: str = ""
        self.source_files: list[tuple[str, str]] = []  # (filename, content)

        self._load()

    def _load(self):
        manifest_path = self._find_manifest()

        # SKILL.md with YAML frontmatter (used by clawhub-installed skills)
        skill_md = self.path / "SKILL.md"
        if not manifest_path and skill_md.exists():
            self.manifest, self.manifest_format = self._parse_skill_md(skill_md)
            self.instructions = self.manifest.pop("_body", "")
            self.name = self.manifest.get("name", self.path.name)
        elif manifest_path:
            self.manifest, self.manifest_format = self._parse_manifest(manifest_path)
            self.name = self.manifest.get("name", self.path.name)
            for candidate in ["instructions.md", "SKILL.md", "skill.md", "Instructions.md"]:
                p = self.path / candidate
                if p.exists():
                    self.instructions = p.read_text(errors="replace")
                    break
        else:
            raise SkillParseError(f"No manifest (claw.json, skill.yaml, or SKILL.md) found in {self.path}")

        for candidate in ["README.md", "readme.md", "Readme.md"]:
            p = self.path / candidate
            if p.exists():
                self.readme = p.read_text(errors="replace")
                break

        src_dir = self.path / "src"
        if src_dir.exists():
            for src_file in src_dir.rglob("*"):
                if src_file.is_file() and src_file.suffix in {".js", ".ts", ".sh", ".py"}:
                    self.source_files.append((str(src_file.relative_to(self.path)), src_file.read_text(errors="replace")))

    def _find_manifest(self) -> Optional[Path]:
        for name in ["claw.json", "skill.yaml", "skill.yml"]:
            p = self.path / name
            if p.exists():
                return p
        return None

    def _parse_skill_md(self, path: Path) -> tuple[dict, str]:
        """Parse a SKILL.md file that has YAML frontmatter (--- ... ---)."""
        text = path.read_text(errors="replace")
        manifest: dict = {}
        body = text
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) >= 3:
                try:
                    manifest = yaml.safe_load(parts[1]) or {}
                except yaml.YAMLError:
                    manifest = {}
                body = parts[2].strip()
        manifest["_body"] = body
        return manifest, "SKILL.md"

    def _parse_manifest(self, path: Path) -> tuple[dict, str]:
        text = path.read_text(errors="replace")
        if path.suffix == ".json":
            try:
                return json.loads(text), "claw.json"
            except json.JSONDecodeError as e:
                raise SkillParseError(f"Invalid JSON in {path}: {e}")
        else:
            try:
                return yaml.safe_load(text) or {}, "skill.yaml"
            except yaml.YAMLError as e:
                raise SkillParseError(f"Invalid YAML in {path}: {e}")

    @property
    def all_text(self) -> str:
        """All text content concatenated for broad pattern matching."""
        parts = [self.instructions, self.readme]
        parts += [content for _, content in self.source_files]
        return "\n".join(parts)

    @property
    def permissions(self) -> list[str]:
        perms = self.manifest.get("permissions", [])
        return [str(p).lower() for p in perms] if isinstance(perms, list) else []

    @property
    def version(self) -> str:
        return str(self.manifest.get("version", "unknown"))

    @property
    def author(self) -> str:
        return str(self.manifest.get("author", "unknown"))
