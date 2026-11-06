"""YAML taxonomy loader and validator for threat detection rules."""

from pathlib import Path
from typing import Any, Dict, List, Tuple
from pydantic import BaseModel, Field
import yaml


class KeywordRuleSchema(BaseModel):
    rule_id: str
    rule_type: str = Field(pattern="^(keyword|phrase|regex|entity)$")
    languages: List[str]
    pattern_payload: Dict[str, Any]
    weight: float = 1.0
    default_severity: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    explanation_template: str
    is_enabled: bool = True
    is_reviewed: bool = False
    taxonomy_version: str = "2026.03.1"


class ThreatCategorySchema(BaseModel):
    category: str
    display_name: str
    description: str
    default_severity: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    is_active: bool = True
    taxonomy_version: str = "2026.03.1"
    rules: List[KeywordRuleSchema]


def load_taxonomy_from_directory(
    taxonomy_dir: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Load and validate all YAML taxonomy rule files from directory.

    Returns:
        (categories, flattened_rules)
    """
    categories: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []

    if not taxonomy_dir.exists():
        return categories, rules

    for yaml_file in sorted(taxonomy_dir.glob("*.yaml")) + sorted(taxonomy_dir.glob("*.yml")):
        with open(yaml_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            continue

        cat_schema = ThreatCategorySchema(**data)
        cat_dict = cat_schema.model_dump()
        raw_rules = cat_dict.pop("rules")

        categories.append(cat_dict)

        for r in raw_rules:
            r["category"] = cat_schema.category
            r["taxonomy_version"] = cat_schema.taxonomy_version
            rules.append(r)

    return categories, rules

