import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").casefold()
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Official domains must be valid hostnames") from exc
    if len(ascii_domain) > 253 or "." not in ascii_domain or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in ascii_domain.split(".")
    ):
        raise ValueError("Official domains must be fully qualified hostnames")
    return ascii_domain


class BrandInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    official_domains: list[str] = Field(min_length=1, max_length=10)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    keywords: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Brand name cannot be blank")
        return value

    @field_validator("official_domains")
    @classmethod
    def clean_domains(cls, values: list[str]) -> list[str]:
        domains = [_normalize_domain(value) for value in values]
        if len(set(domains)) != len(domains):
            raise ValueError("Official domains must be unique")
        return domains

    @field_validator("aliases", "keywords")
    @classmethod
    def clean_terms(cls, values: list[str]) -> list[str]:
        normalized = [item.strip() for item in values if item.strip()]
        return list(dict.fromkeys(normalized))


class BrandView(BrandInput):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
