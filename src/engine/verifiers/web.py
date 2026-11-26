"""WebCitationVerifier enforcing primary OEM citations and explicit not_documented (CB-08)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlparse

from pydantic import Field

from src.adapters.web_search import WebPageExtract
from src.contracts.common import FrozenModel, NonEmptyStr
from src.contracts.envelope import VerdictState

_GENERIC_CORP_TOKENS: frozenset[str] = frozenset(
    {
        "electric",
        "electrical",
        "electronics",
        "group",
        "ltd",
        "limited",
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "gmbh",
        "ag",
        "sa",
        "sas",
        "srl",
        "spa",
        "bv",
        "nv",
        "llc",
        "llp",
        "plc",
        "co",
        "company",
        "automation",
        "controls",
        "control",
        "systems",
        "system",
        "industrial",
        "industries",
        "industry",
        "technologies",
        "technology",
        "tech",
        "energy",
        "solutions",
        "global",
        "international",
        "intl",
        "instruments",
        "instrumentation",
        "process",
        "engineering",
        "usa",
        "europe",
        "america",
        "the",
        "and",
    }
)


class ClaimedSpecField(FrozenModel):
    """Single claimed specification attribute paired with its alleged source URL and date."""

    field_name: NonEmptyStr
    value: str | None = None
    source_url: str | None = None
    observed_date: str | None = None


class WebVerificationReport(FrozenModel):
    """Verification verdict returned by WebCitationVerifier."""

    verdict: VerdictState
    passed: bool
    primary_oem_urls: tuple[str, ...] = ()
    manufacturer: str | None = None
    model: str | None = None
    citation_date: str | None = None
    documented_fields: dict[str, str] = Field(default_factory=dict)
    not_documented_fields: tuple[str, ...] = ()
    unverified_urls: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


class WebCitationVerifier:
    """Fail-closed verifier requiring consulted primary OEM sources and honest gaps."""

    @staticmethod
    def _normalize_url(url: str) -> str:
        return url.strip().rstrip("/")

    @staticmethod
    def _url_matches_manufacturer(url: str, manufacturer: str | None) -> bool:
        if not manufacturer:
            return False
        host = (urlparse(url).hostname or "").strip().lower()
        if not host:
            return False
        brand_tokens = [
            tok
            for tok in re.findall(r"[a-z0-9]+", manufacturer.lower())
            if len(tok) >= 3 and tok not in _GENERIC_CORP_TOKENS
        ]
        if not brand_tokens:
            return False
        labels = [lbl for lbl in host.split(".") if lbl]
        if not labels:
            return False
        if (
            len(labels) >= 3
            and len(labels[-1]) == 2
            and labels[-2] in {"co", "com", "org", "net", "gov", "edu"}
        ):
            reg_label = labels[-3]
        elif len(labels) >= 2:
            reg_label = labels[-2]
        else:
            reg_label = labels[0]
        reg_parts = reg_label.split("-")
        return any(
            tok == reg_label or tok in reg_parts or (len(tok) >= 5 and tok in reg_label)
            for tok in brand_tokens
        )

    def verify(
        self,
        *,
        manufacturer: str | None,
        model: str | None,
        citation_date: str | None,
        claimed_fields: Sequence[ClaimedSpecField],
        fetched_pages: Sequence[WebPageExtract],
        required_attributes: Sequence[str] = (),
        oem_domains: Sequence[str] = (),
    ) -> WebVerificationReport:
        """Verify all claims trace to consulted in-turn pages and primary OEM sources."""
        consulted_by_url: dict[str, WebPageExtract] = {}
        non_2xx_by_url: dict[str, WebPageExtract] = {}
        for page in fetched_pages:
            if 200 <= page.status_code < 300:
                consulted_by_url[self._normalize_url(page.url)] = page
                consulted_by_url[self._normalize_url(page.final_url)] = page
            else:
                non_2xx_by_url[self._normalize_url(page.url)] = page
                non_2xx_by_url[self._normalize_url(page.final_url)] = page

        errors: list[str] = []
        unverified_urls: list[str] = []
        primary_oem_urls: list[str] = []

        if not manufacturer or not manufacturer.strip():
            errors.append("Missing manufacturer attribution.")
        if not model or not model.strip():
            errors.append("Missing model identifier.")
        if not citation_date or not citation_date.strip():
            errors.append("Missing citation_date.")

        oem_domain_set = tuple(d.strip().lower().lstrip(".") for d in oem_domains if d.strip())

        def _is_primary(page: WebPageExtract) -> bool:
            if page.is_primary_oem:
                return True
            host = (urlparse(page.final_url).hostname or "").strip().lower()
            if any(host == d or host.endswith(f".{d}") for d in oem_domain_set):
                return True
            return self._url_matches_manufacturer(page.final_url, manufacturer)

        for page in fetched_pages:
            if (
                200 <= page.status_code < 300
                and _is_primary(page)
                and page.final_url not in primary_oem_urls
            ):
                primary_oem_urls.append(page.final_url)

        documented_fields: dict[str, str] = {}
        not_documented_fields: list[str] = []

        for claim in claimed_fields:
            fname = claim.field_name.strip()
            val_str = claim.value.strip() if isinstance(claim.value, str) else None
            if val_str is None or val_str.lower() in {"", "not_documented", "n/a", "unknown"}:
                documented_fields[fname] = "not_documented"
                if fname not in not_documented_fields:
                    not_documented_fields.append(fname)
                continue

            if not claim.source_url:
                errors.append(f"Claimed field {fname!r} has value without source_url citation.")
                continue

            norm_src = self._normalize_url(claim.source_url)
            matched_page = consulted_by_url.get(norm_src)
            if matched_page is None:
                unverified_urls.append(claim.source_url)
                bad_page = non_2xx_by_url.get(norm_src)
                if bad_page is not None:
                    errors.append(
                        f"Cited URL {claim.source_url!r} returned non-2xx HTTP status "
                        f"{bad_page.status_code}."
                    )
                else:
                    errors.append(
                        f"Fabricated or unconsulted URL cited for {fname!r}: {claim.source_url!r}."
                    )
                continue

            # Grounding check: claimed value or key token must appear in page text/specs
            haystack = (
                matched_page.text_excerpt.lower()
                + " "
                + " ".join(f"{k} {v}".lower() for k, v in matched_page.extracted_specs.items())
            )
            if val_str.lower() not in haystack:
                errors.append(
                    f"Claimed value {val_str!r} for {fname!r} not grounded in consulted page "
                    f"{matched_page.final_url!r}."
                )
                continue

            documented_fields[fname] = val_str

        # Ensure every required attribute is either documented or explicitly not_documented
        for req_attr in required_attributes:
            req_clean = req_attr.strip()
            if not req_clean:
                continue
            if req_clean not in documented_fields:
                documented_fields[req_clean] = "not_documented"
                if req_clean not in not_documented_fields:
                    not_documented_fields.append(req_clean)

        if not primary_oem_urls:
            errors.append("No primary OEM source URL was consulted during this turn.")

        if unverified_urls or errors:
            verdict = VerdictState.CONTRADICTED
            passed = False
        elif not_documented_fields and not any(
            v != "not_documented" for v in documented_fields.values()
        ):
            verdict = VerdictState.NOT_DOCUMENTED
            passed = True
        elif not_documented_fields:
            # Core specs verified from OEM while optional/discontinued fields are not_documented
            verdict = VerdictState.VERIFIED
            passed = True
        else:
            verdict = VerdictState.VERIFIED
            passed = True

        return WebVerificationReport(
            verdict=verdict,
            passed=passed,
            primary_oem_urls=tuple(primary_oem_urls),
            manufacturer=manufacturer.strip() if manufacturer else None,
            model=model.strip() if model else None,
            citation_date=citation_date.strip() if citation_date else None,
            documented_fields=documented_fields,
            not_documented_fields=tuple(not_documented_fields),
            unverified_urls=tuple(unverified_urls),
            errors=tuple(errors),
        )


__all__ = [
    "ClaimedSpecField",
    "WebCitationVerifier",
    "WebVerificationReport",
]
