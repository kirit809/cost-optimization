from typing import Iterable

def tags_to_dict(tags):
    return {item.get("Key", ""): item.get("Value", "") for item in (tags or [])}

def missing_tags(tags: dict[str, str], required: Iterable[str]) -> list[str]:
    return sorted(key for key in required if not tags.get(key, "").strip())
