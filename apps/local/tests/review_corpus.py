"""Versioned review corpus of deliberately planted defects.

Every case starts from one real published run -- the actual CSV, PNG, Markdown
and evidence-ledger bytes the pipeline produced -- and applies exactly one
mutation. That is what makes a measured catch rate mean anything: the Reviewer
is scored against evidence it would really see, not against hand-written
fixtures shaped to match its parser.

Two mutation techniques exist and they are not interchangeable.

*Counterfactual publications* model a run that really did publish the defective
bytes. Their digests, sizes, and ledger entries are re-derived so the mutated
artifact is internally consistent. Without that, every case would also be an
RV03 checksum mismatch and the corpus would only ever be measuring one rule.

*Tampering* models bytes altered after commit. Digests are deliberately left
alone, which is exactly the disagreement RV03 exists to catch.

Three case kinds, and what each one measures
--------------------------------------------
`PLANTED` carries a defect that falls inside the declared `checks` of one
named rule in `reviewer.RULE_COVERAGE`. The rule must report `fail`. A miss is
a defect in the Reviewer, never a reason to soften the case.

`CLEAN` carries no defect and measures false positives. An `inconclusive`
verdict is not scored against the false-positive budget: the specification
requires unreachable evidence to be `inconclusive`, and requires that outcome
not to be counted as a false positive. `fail` and `warn` are.

`DISCLOSED_LIMIT` carries a *real* defect that the named rule's published
`limits` say it structurally cannot see. The rule must not report `fail`, and
each such case names the substring of the published limit that covers it. This
is what turns `RULE_COVERAGE` from prose into a measurement: a limit that is
deleted, or narrowed to claim more coverage than the code has, fails the
suite. These cases are excluded from both rates on purpose -- scoring a
disclosed structural gap as a miss would let a rewrite of the disclosure move
the catch rate, which is exactly backwards.

Read the numbers accordingly. The catch rate is over defects the Reviewer
claims to cover. The count of disclosed limits is the part it does not, and
that count is the honest ceiling on what a green gate here means.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Final, cast, final, override

from services.api.artifacts.models import ArtifactScope

from nipo_local.config import LOCAL_USER_ID
from nipo_local.reviewer import (
    CitedIdentifier,
    IdentifierResolution,
    IdentifierResolver,
    Reviewer,
)
from nipo_local.store import (
    ContentState,
    LocalArtifactStore,
    PinnedOutput,
    PinnedRunEvidence,
    ReviewRuleId,
    ReviewVerdict,
)

if TYPE_CHECKING:
    from collections.abc import Callable

CORPUS_VERSION: Final = "nipo.local.review-corpus.v2"

MISSING_MUTATION: Final = "corpus mutation matched nothing in the pinned bytes"
UNEXPECTED_LEDGER_SHAPE: Final = "pinned ledger is not the document the producer wrote"
MISSING_DIGEST_LINE: Final = "pinned report does not carry the digest line to mutate"
CASE_SHAPE: Final = "corpus case does not match the shape its kind requires"

CSV_ROLE: Final = "csv"
PNG_ROLE: Final = "png"
MARKDOWN_ROLE: Final = "markdown"
LEDGER_ROLE: Final = "ledger"

DEMO_DOI: Final = "10.1234/nipo.demo.2026"
OTHER_DOI: Final = "10.5555/nipo.demo.2027"
DEMO_PMID: Final = "40011223"
DEMO_OPENALEX: Final = "W2741809807"

_RATIONALE: Final = "- Rationale: "
_MOLECULAR_OBSERVATION: Final = "local maximum at 430 nm."
_MOLECULAR_CONTROL: Final = (
    "Compare a reference-standard spectrum under the same conditions."
)
_BRANCH_LIMITATION: Final = (
    "- Limitation: Research-support observation only; causality is not established."
)
_REPORT_LIMITATION: Final = "- Research-support output only."
_DIGEST_PREFIX: Final = "- Canonical digest: `"


class CaseKind(StrEnum):
    """What one corpus case is evidence of."""

    PLANTED = "planted"
    CLEAN = "clean"
    DISCLOSED_LIMIT = "disclosed_limit"


@final
class UnsupportedIdentifierResolver(IdentifierResolver):
    """Report every identifier as resolved but not supporting its claim."""

    @override
    def resolve(self, identifier: CitedIdentifier) -> IdentifierResolution:
        del identifier
        return IdentifierResolution.UNSUPPORTED


@final
class MappedIdentifierResolver(IdentifierResolver):
    """Answer for exactly the identifiers a case says were cited.

    Anything else is `UNSUPPORTED`, which is deliberate: an identifier the
    Reviewer manufactured by mis-reading the surrounding punctuation is not
    the one the author cited, and a clean case must fail loudly rather than
    quietly resolve a value nobody wrote.
    """

    def __init__(
        self,
        supported: tuple[str, ...] = (),
        unreachable: tuple[str, ...] = (),
    ) -> None:
        """Bind the exact identifiers this case cited and their outcomes."""
        self._supported = frozenset(supported)
        self._unreachable = frozenset(unreachable)

    @override
    def resolve(self, identifier: CitedIdentifier) -> IdentifierResolution:
        if identifier.value in self._supported:
            return IdentifierResolution.SUPPORTED
        if identifier.value in self._unreachable:
            return IdentifierResolution.UNREACHABLE
        return IdentifierResolution.UNSUPPORTED


@dataclass(frozen=True, slots=True)
class CorpusCase:
    """One corpus entry, its planted defect, and the outcome it expects."""

    case_id: str
    kind: CaseKind
    defect: str
    expected_rule: ReviewRuleId | None
    expected_verdict: ReviewVerdict
    mutate: Callable[[PinnedRunEvidence], PinnedRunEvidence]
    resolver: IdentifierResolver | None = None
    # Every published sentence this case depends on, so the whole disclosure
    # is load-bearing rather than only the clause a single assertion happened
    # to quote.
    limit_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Refuse a case whose fields do not match the kind it declares."""
        if self.kind is CaseKind.CLEAN:
            if self.expected_rule is not None or self.limit_evidence:
                raise ValueError(CASE_SHAPE)
            return
        if self.expected_rule is None:
            raise ValueError(CASE_SHAPE)
        if bool(self.limit_evidence) is not (self.kind is CaseKind.DISCLOSED_LIMIT):
            raise ValueError(CASE_SHAPE)

    @property
    def planted(self) -> bool:
        """Return whether this case carries a defect the Reviewer must catch."""
        return self.kind is CaseKind.PLANTED


@dataclass(frozen=True, slots=True)
class CaseResult:
    """One scored case: what the Reviewer said and whether that was right."""

    case: CorpusCase
    verdict: ReviewVerdict
    rule_verdict: ReviewVerdict | None
    caught: bool
    false_positive: bool
    limit_held: bool

    @property
    def verdict_matched(self) -> bool:
        """Return whether the summary verdict was the one this case declared."""
        return self.verdict is self.case.expected_verdict


@dataclass(frozen=True, slots=True)
class CorpusScore:
    """The measured outcome of one whole corpus run."""

    corpus_version: str
    results: tuple[CaseResult, ...]

    @property
    def planted(self) -> int:
        """Return how many cases carried a planted defect."""
        return sum(1 for item in self.results if item.case.kind is CaseKind.PLANTED)

    @property
    def caught(self) -> int:
        """Return how many planted defects the expected rule reported `fail`."""
        return sum(1 for item in self.results if item.caught)

    @property
    def clean(self) -> int:
        """Return how many cases carried no defect at all."""
        return sum(1 for item in self.results if item.case.kind is CaseKind.CLEAN)

    @property
    def false_positives(self) -> int:
        """Return how many clean cases drew a `fail` or `warn` verdict."""
        return sum(1 for item in self.results if item.false_positive)

    @property
    def disclosed_limits(self) -> int:
        """Return how many cases sit outside every rule's declared coverage."""
        return sum(
            1 for item in self.results if item.case.kind is CaseKind.DISCLOSED_LIMIT
        )

    @property
    def catch_rate(self) -> float:
        """Return caught defects over planted defects."""
        return self.caught / self.planted if self.planted else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Return false positives over clean cases."""
        return self.false_positives / self.clean if self.clean else 0.0

    @property
    def missed(self) -> tuple[str, ...]:
        """Name every planted defect the Reviewer failed to catch."""
        return tuple(
            item.case.case_id
            for item in self.results
            if item.case.kind is CaseKind.PLANTED and not item.caught
        )

    @property
    def overstated_limits(self) -> tuple[str, ...]:
        """Name every disclosed limit the Reviewer turned out to cover.

        Catching one of these is not a failure of the Reviewer; it is a
        failure of the disclosure, which now claims a gap that is closed.
        """
        return tuple(
            item.case.case_id
            for item in self.results
            if item.case.kind is CaseKind.DISCLOSED_LIMIT and not item.limit_held
        )

    @property
    def wrong_summary_verdict(self) -> tuple[str, ...]:
        """Name every case whose whole-Review verdict was not the declared one."""
        return tuple(
            item.case.case_id for item in self.results if not item.verdict_matched
        )


def score_corpus(baseline: PinnedRunEvidence) -> CorpusScore:
    """Run every corpus case against one real baseline and score the results."""
    return CorpusScore(
        corpus_version=CORPUS_VERSION,
        results=tuple(_score_case(case, baseline) for case in CORPUS),
    )


def _score_case(case: CorpusCase, baseline: PinnedRunEvidence) -> CaseResult:
    """Review one mutated snapshot and decide whether the Reviewer was right."""
    outcome = Reviewer(case.mutate(baseline), case.resolver).review()
    by_rule = {item.rule_id: item.verdict for item in outcome.findings}
    rule_verdict = None if case.expected_rule is None else by_rule[case.expected_rule]
    return CaseResult(
        case=case,
        verdict=outcome.verdict,
        rule_verdict=rule_verdict,
        caught=case.kind is CaseKind.PLANTED and rule_verdict is ReviewVerdict.FAIL,
        # `inconclusive` is excluded here on purpose: RV02 requires unreachable
        # evidence to be inconclusive, and that outcome must never be scored
        # against the false-positive budget.
        false_positive=case.kind is CaseKind.CLEAN
        and any(
            item.verdict in {ReviewVerdict.FAIL, ReviewVerdict.WARN}
            for item in outcome.findings
        ),
        limit_held=case.kind is CaseKind.DISCLOSED_LIMIT
        and rule_verdict is not ReviewVerdict.FAIL,
    )


def _output(evidence: PinnedRunEvidence, role: str) -> PinnedOutput:
    """Return the one pinned output published under a chain role."""
    return next(item for item in evidence.outputs if item.role == role)


def _content(evidence: PinnedRunEvidence, role: str) -> bytes:
    """Return one pinned output's bytes, refusing an unreadable baseline."""
    payload = _output(evidence, role).content
    if payload is None:
        raise ValueError(MISSING_MUTATION)
    return payload


def _replace_once(text: str, old: str, new: str) -> str:
    """Apply one required substitution, refusing to plant nothing at all.

    A corpus mutation that silently matched nothing would inflate the measured
    catch rate with a case that never carried a defect.
    """
    if old not in text:
        raise ValueError(MISSING_MUTATION)
    return text.replace(old, new, 1)


def _republished(
    evidence: PinnedRunEvidence,
    role: str,
    payload: bytes,
) -> PinnedOutput:
    """Rebuild one output as if the run had published these bytes instead."""
    original = _output(evidence, role)
    version = original.version
    if version is None:
        raise ValueError(MISSING_MUTATION)
    digest = hashlib.sha256(payload).hexdigest()
    scope = ArtifactScope(
        org_id=version.org_id,
        project_id=version.project_id,
        requester_id=LOCAL_USER_ID,
    )
    return replace(
        original,
        recorded_sha256=digest,
        content=payload,
        content_state=ContentState.AVAILABLE,
        version=version.model_copy(
            update={
                "content_sha256": digest,
                "size_bytes": len(payload),
                "object_key": LocalArtifactStore.object_key(scope, digest),
            }
        ),
    )


def _with_outputs(
    evidence: PinnedRunEvidence,
    updated: dict[str, PinnedOutput],
) -> PinnedRunEvidence:
    """Return the snapshot with named roles swapped for replacement outputs."""
    return replace(
        evidence,
        outputs=tuple(updated.get(item.role, item) for item in evidence.outputs),
    )


def ledger_document(evidence: PinnedRunEvidence) -> dict[str, object]:
    """Decode the pinned evidence ledger into a mutable document."""
    document = cast("object", json.loads(_content(evidence, LEDGER_ROLE)))
    if not isinstance(document, dict):
        raise TypeError(UNEXPECTED_LEDGER_SHAPE)
    return copy.deepcopy(cast("dict[str, object]", document))


def ledger_bytes(document: dict[str, object]) -> bytes:
    """Re-render one ledger document in the producer's canonical form."""
    return json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def ledger_entries(document: dict[str, object], key: str) -> list[dict[str, object]]:
    """Return one ledger list section, refusing a shape the producer never wrote."""
    section: object = document[key]
    if not isinstance(section, list):
        raise TypeError(UNEXPECTED_LEDGER_SHAPE)
    entries: list[dict[str, object]] = []
    for item in cast("list[object]", section):
        if not isinstance(item, dict):
            raise TypeError(UNEXPECTED_LEDGER_SHAPE)
        entries.append(cast("dict[str, object]", item))
    return entries


def republish_text(
    evidence: PinnedRunEvidence,
    role: str,
    old: str,
    new: str,
) -> PinnedRunEvidence:
    """Publish one text output with a substitution and keep the ledger honest.

    The ledger entry for the rewritten role is updated and the ledger itself
    re-derived, so the only defect left in the snapshot is the substitution.
    """
    payload = _replace_once(_content(evidence, role).decode(), old, new).encode()
    rewritten = _republished(evidence, role, payload)
    document = ledger_document(evidence)
    for entry in ledger_entries(document, "outputs"):
        if entry.get("role") == role:
            entry["content_sha256"] = hashlib.sha256(payload).hexdigest()
            entry["size_bytes"] = len(payload)
    staged = _with_outputs(evidence, {role: rewritten})
    ledger = _republished(staged, LEDGER_ROLE, ledger_bytes(document))
    return _with_outputs(staged, {role: rewritten, LEDGER_ROLE: ledger})


def republish_ledger(
    evidence: PinnedRunEvidence,
    edit: Callable[[dict[str, object]], None],
) -> PinnedRunEvidence:
    """Publish an edited evidence ledger with its own digest re-derived."""
    document = ledger_document(evidence)
    edit(document)
    return _with_outputs(
        evidence,
        {LEDGER_ROLE: _republished(evidence, LEDGER_ROLE, ledger_bytes(document))},
    )


def _cite_in_rationale(text: str) -> Callable[[PinnedRunEvidence], PinnedRunEvidence]:
    """Build a mutation that adds one citation sentence to the rationale."""

    def mutate(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
        return republish_text(
            evidence,
            MARKDOWN_ROLE,
            _RATIONALE,
            f"{_RATIONALE}{text} ",
        )

    return mutate


def _unchanged(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Return the real baseline untouched."""
    return evidence


# --------------------------------------------------------------------------
# RV01: numeric claims against the pinned execution output.
# --------------------------------------------------------------------------


def _numeric_claim_unsupported(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report whose peak wavelength the pinned CSV does not carry."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        f"- Observation: Calibrated corrected signal has a {_MOLECULAR_OBSERVATION}",
        "- Observation: Calibrated corrected signal has a local maximum at 999 nm.",
    )


def _wavelength_off_by_one_digit(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report whose peak wavelength differs from the CSV by one digit."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        _MOLECULAR_OBSERVATION,
        "local maximum at 431 nm.",
    )


def _missingness_off_by_one_digit(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report whose missingness differs from the CSV in one decimal."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        "maximum table missingness is 0.000000.",
        "maximum table missingness is 0.010000.",
    )


def _peak_count_inflated(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report claiming more peaks than its own pinned table lists."""
    return republish_text(evidence, MARKDOWN_ROLE, "- Peaks: 3", "- Peaks: 5")


def _peak_row_dropped(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report that drops a peak row but keeps its declared count."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        "| 5 | 450 | 0.158333 | 0.041666 |\n",
        "",
    )


def _peak_table_value_drift(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report whose peak table wavelength drifted by one digit.

    No pinned machine-readable spectrum output exists, so this value has
    nothing independent to be traced to. RV01 discloses that.
    """
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        "| 3 | 430 | 0.425000 | 0.308333 |",
        "| 3 | 431 | 0.425000 | 0.308333 |",
    )


def _consistent_counterfactual(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a wrong peak in both the report and the CSV, consistently.

    Every digest, size and ledger entry is re-derived, so nothing in the
    pinned record disagrees with anything else. Only re-running the analysis
    would show the number is wrong, and no rule re-runs anything.
    """
    rewritten = republish_text(
        evidence,
        MARKDOWN_ROLE,
        _MOLECULAR_OBSERVATION,
        "local maximum at 999 nm.",
    )
    return republish_text(
        rewritten,
        CSV_ROLE,
        _MOLECULAR_OBSERVATION,
        "local maximum at 999 nm.",
    )


def _equivalent_number_formatting(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish the same peak wavelength written with a decimal tail."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        _MOLECULAR_OBSERVATION,
        "local maximum at 430.0 nm.",
    )


def _number_outside_the_compared_region(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish a legitimate new number in the closing limitations section."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        _REPORT_LIMITATION,
        f"{_REPORT_LIMITATION}\n- Acquisition used 3 replicate scans at 12 ms.",
    )


def _number_in_a_report_control(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a branch control naming a replicate count the CSV never listed."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        f"- Control: {_MOLECULAR_CONTROL}",
        "- Control: Compare a reference-standard spectrum across 3 replicates.",
    )


# --------------------------------------------------------------------------
# RV02: cited identifiers.
# --------------------------------------------------------------------------


def _cited_identifier(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report citing a DOI this offline machine cannot resolve."""
    return _cite_in_rationale(f"See doi:{DEMO_DOI}.")(evidence)


def _three_identifiers_cited(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report citing two DOIs and one PubMed identifier."""
    return _cite_in_rationale(f"See {DEMO_DOI}, {OTHER_DOI} and PMID: {DEMO_PMID}.")(
        evidence
    )


def _doi_inside_a_parenthetical(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report citing a DOI inside brackets, as authors really write."""
    return _cite_in_rationale(f"(doi:{DEMO_DOI})")(evidence)


def _sample_code_that_is_not_a_citation(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish text carrying an OpenAlex-shaped code and a DOI-shaped prefix."""
    return _cite_in_rationale(f"Sample {DEMO_OPENALEX} from lot 10.1234 was used.")(
        evidence
    )


def _openalex_cited(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report citing one prefixed OpenAlex work identifier."""
    return _cite_in_rationale(f"See openalex:{DEMO_OPENALEX}.")(evidence)


def _pubmed_cited(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report citing one PubMed identifier."""
    return _cite_in_rationale(f"See PMID: {DEMO_PMID}.")(evidence)


def _two_identifiers_cited(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report citing one checkable and one unreachable identifier."""
    return _cite_in_rationale(f"See {DEMO_DOI} and {OTHER_DOI}.")(evidence)


def _identifier_attached_to_a_branch(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish a branch limitation citing a resolvable, unrelated reference.

    The identifier resolves and supports its own paper's claim. Nothing in the
    pinned record binds it to *this* branch, and RV02 discloses that it cannot
    establish the binding.
    """
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        _BRANCH_LIMITATION,
        f"{_BRANCH_LIMITATION} Supporting reference: {DEMO_DOI}.",
    )


# --------------------------------------------------------------------------
# RV03: correspondence between pinned records.
# --------------------------------------------------------------------------


def _figure_tampered(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Alter the published figure after commit, leaving its digests behind."""
    return _with_outputs(
        evidence,
        {
            PNG_ROLE: replace(
                _output(evidence, PNG_ROLE),
                content=None,
                content_state=ContentState.TAMPERED,
            )
        },
    )


def _ledger_figure_digest_rewritten(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish a ledger claiming a figure checksum the Version never had."""

    def edit(document: dict[str, object]) -> None:
        for entry in ledger_entries(document, "outputs"):
            if entry.get("role") == PNG_ROLE:
                entry["content_sha256"] = "f" * 64

    return republish_ledger(evidence, edit)


def _ledger_media_type_drift(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a ledger describing the figure as a table."""

    def edit(document: dict[str, object]) -> None:
        for entry in ledger_entries(document, "outputs"):
            if entry.get("role") == PNG_ROLE:
                entry["media_type"] = "text/csv"

    return republish_ledger(evidence, edit)


def _ledger_version_no_off_by_one(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a ledger pinning the table one Version later than it committed."""

    def edit(document: dict[str, object]) -> None:
        for entry in ledger_entries(document, "outputs"):
            if entry.get("role") == CSV_ROLE:
                entry["version_no"] = 2

    return republish_ledger(evidence, edit)


def _ledger_omits_the_figure(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a ledger that never mentions the figure the run committed."""

    def edit(document: dict[str, object]) -> None:
        document["outputs"] = [
            entry
            for entry in ledger_entries(document, "outputs")
            if entry.get("role") != PNG_ROLE
        ]

    return republish_ledger(evidence, edit)


def _ledger_overstates_isolation(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a ledger claiming confinement the execution never recorded."""

    def edit(document: dict[str, object]) -> None:
        document["execution_isolation"] = "sandboxed"

    return republish_ledger(evidence, edit)


def _code_digest_drift(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Pin a figure to code that is not the code the execution recorded."""
    original = _output(evidence, PNG_ROLE)
    version = original.version
    if version is None:
        raise ValueError(MISSING_MUTATION)
    return _with_outputs(
        evidence,
        {
            PNG_ROLE: replace(
                original,
                version=version.model_copy(update={"code_sha256": "e" * 64}),
            )
        },
    )


def _report_input_digest_off_by_one(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report whose declared input digest differs in one character.

    The digest is read out of the real report rather than written here, so
    this case cannot rot into a no-op when the pinned input changes.
    """
    lines = [
        line
        for line in _content(evidence, MARKDOWN_ROLE).decode().split("\n")
        if line.startswith(_DIGEST_PREFIX)
    ]
    expected_lines = 2
    if len(lines) < expected_lines:
        raise ValueError(MISSING_DIGEST_LINE)
    declared = lines[1]
    flipped = declared[:-2] + ("0" if declared[-2] != "0" else "1") + "`"
    return republish_text(evidence, MARKDOWN_ROLE, declared, flipped)


# --------------------------------------------------------------------------
# RV04: stated evidence level against the level retrieved.
# --------------------------------------------------------------------------


def _evidence_level_escalated(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a ledger deriving an observation from an insufficient branch."""

    def edit(document: dict[str, object]) -> None:
        for entry in ledger_entries(document, "science_evidence"):
            if entry.get("branch") == "optical":
                entry["evidence_kind"] = "derived_observation"

    return republish_ledger(evidence, edit)


def _report_state_escalated(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report stating a branch two levels above the pinned CSV."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        "### optical (insufficient)",
        "### optical (observed)",
    )


def _report_state_escalated_one_step(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish a report stating a branch exactly one level above the CSV."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        "### optical (insufficient)",
        "### optical (plausible)",
    )


def _report_state_outside_the_vocabulary(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish a branch state the science package never defines.

    `confirmed` reads as a stronger claim than `plausible` to a human, but
    nothing pinned ranks it, so RV04 discloses that it cannot say which way
    the claim moved.
    """
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        "### molecular (plausible)",
        "### molecular (confirmed)",
    )


def _branch_absent_from_the_pinned_table(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish a hypothesis branch the pinned CSV never carried."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        "## Analysis issues",
        "### spectral (observed)\n\n"
        "- Observation: The corrected band is reproducible across replicates.\n"
        f"- Control: {_MOLECULAR_CONTROL}\n"
        f"{_BRANCH_LIMITATION}\n"
        "- Conclusion scope: non_diagnostic\n\n"
        "## Analysis issues",
    )


# --------------------------------------------------------------------------
# RV05: research-only, non-clinical limits.
# --------------------------------------------------------------------------


def _clinical_claim(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a report that crosses the research-only, non-clinical boundary."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        f"- Observation: Calibrated corrected signal has a {_MOLECULAR_OBSERVATION}",
        (
            "- Observation: The 430 nm band confirms the patient diagnosis and "
            "supports starting treatment."
        ),
    )


def _dosing_instruction_in_a_control(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish a hypothesis control written as a dosing instruction."""
    return republish_text(
        evidence,
        CSV_ROLE,
        _MOLECULAR_CONTROL,
        "Confirm the dosing interval before repeating the acquisition.",
    )


def _scope_marker_dropped(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a hypothesis table whose row drops its non-diagnostic scope."""
    return republish_text(
        evidence,
        CSV_ROLE,
        "under the same conditions.,non_diagnostic",
        "under the same conditions.,advisory",
    )


def _branch_limitation_dropped(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a branch whose limitation line was removed before publication."""
    return republish_text(evidence, MARKDOWN_ROLE, f"{_BRANCH_LIMITATION}\n", "")


def _negated_boundary_marker(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a limitation that declares a boundary using a negated term."""
    return republish_text(
        evidence,
        MARKDOWN_ROLE,
        _REPORT_LIMITATION,
        "- Research-support, non-therapeutic output only.",
    )


def _heat_treatment_control(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    """Publish a materials-science control that reuses a clinical word.

    Nothing here crosses the research-only boundary. RV05 is a lexical scan
    with no way to read context, so this is the measured false positive.
    """
    return republish_text(
        evidence,
        CSV_ROLE,
        "Repeat acquisition with randomized order and independent controls.",
        "Repeat acquisition after heat treatment of the reference coupon.",
    )


def _guidance_without_boundary_vocabulary(
    evidence: PinnedRunEvidence,
) -> PinnedRunEvidence:
    """Publish unsafe guidance written without any boundary term at all."""
    return republish_text(
        evidence,
        CSV_ROLE,
        _MOLECULAR_CONTROL,
        "Administer 5 mg to the subject each morning and record the response.",
    )


_PLANTED: Final = (
    CorpusCase(
        case_id="rv01-numeric-claim-unsupported",
        kind=CaseKind.PLANTED,
        defect="report claims a peak wavelength absent from the pinned CSV",
        expected_rule=ReviewRuleId.RV01,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_numeric_claim_unsupported,
    ),
    CorpusCase(
        case_id="rv01-wavelength-off-by-one-digit",
        kind=CaseKind.PLANTED,
        defect="report wavelength differs from the pinned CSV by one digit",
        expected_rule=ReviewRuleId.RV01,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_wavelength_off_by_one_digit,
    ),
    CorpusCase(
        case_id="rv01-missingness-off-by-one-digit",
        kind=CaseKind.PLANTED,
        defect="report missingness differs from the pinned CSV in one decimal",
        expected_rule=ReviewRuleId.RV01,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_missingness_off_by_one_digit,
    ),
    CorpusCase(
        case_id="rv01-peak-count-inflated",
        kind=CaseKind.PLANTED,
        defect="report declares more peaks than its own pinned table lists",
        expected_rule=ReviewRuleId.RV01,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_peak_count_inflated,
    ),
    CorpusCase(
        case_id="rv01-peak-row-dropped-count-kept",
        kind=CaseKind.PLANTED,
        defect="report drops a peak row while keeping its declared peak count",
        expected_rule=ReviewRuleId.RV01,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_peak_row_dropped,
    ),
    CorpusCase(
        case_id="rv02-identifier-does-not-support-claim",
        kind=CaseKind.PLANTED,
        defect="a cited DOI resolves but does not support the claim made",
        expected_rule=ReviewRuleId.RV02,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_cited_identifier,
        resolver=UnsupportedIdentifierResolver(),
    ),
    CorpusCase(
        case_id="rv02-one-of-three-identifiers-unsupported",
        kind=CaseKind.PLANTED,
        defect="two cited identifiers support the claim and the third does not",
        expected_rule=ReviewRuleId.RV02,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_three_identifiers_cited,
        resolver=MappedIdentifierResolver(supported=(DEMO_DOI, DEMO_PMID)),
    ),
    CorpusCase(
        case_id="rv03-figure-tampered-after-commit",
        kind=CaseKind.PLANTED,
        defect="figure bytes altered after commit; digests left untouched",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_figure_tampered,
    ),
    CorpusCase(
        case_id="rv03-ledger-figure-digest-rewritten",
        kind=CaseKind.PLANTED,
        defect="ledger pins a figure checksum the Version never carried",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_ledger_figure_digest_rewritten,
    ),
    CorpusCase(
        case_id="rv03-ledger-media-type-drift",
        kind=CaseKind.PLANTED,
        defect="ledger describes the figure as a table the Version never was",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_ledger_media_type_drift,
    ),
    CorpusCase(
        case_id="rv03-ledger-version-no-off-by-one",
        kind=CaseKind.PLANTED,
        defect="ledger pins the table one Version later than it was committed",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_ledger_version_no_off_by_one,
    ),
    CorpusCase(
        case_id="rv03-ledger-omits-the-figure",
        kind=CaseKind.PLANTED,
        defect="ledger never mentions a figure the run really committed",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_ledger_omits_the_figure,
    ),
    CorpusCase(
        case_id="rv03-ledger-overstates-isolation",
        kind=CaseKind.PLANTED,
        defect="ledger claims confinement the pinned execution never recorded",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_ledger_overstates_isolation,
    ),
    CorpusCase(
        case_id="rv03-code-digest-drift",
        kind=CaseKind.PLANTED,
        defect="figure pins code that is not the code the execution recorded",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_code_digest_drift,
    ),
    CorpusCase(
        case_id="rv03-report-input-digest-off-by-one",
        kind=CaseKind.PLANTED,
        defect="report declares an input digest differing in one character",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_report_input_digest_off_by_one,
    ),
    CorpusCase(
        case_id="rv04-evidence-level-escalated",
        kind=CaseKind.PLANTED,
        defect="ledger derives an observation from an insufficient branch",
        expected_rule=ReviewRuleId.RV04,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_evidence_level_escalated,
    ),
    CorpusCase(
        case_id="rv04-report-state-escalated",
        kind=CaseKind.PLANTED,
        defect="report states a branch two levels above the pinned CSV",
        expected_rule=ReviewRuleId.RV04,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_report_state_escalated,
    ),
    CorpusCase(
        case_id="rv04-report-state-escalated-by-one-step",
        kind=CaseKind.PLANTED,
        defect="report states a branch exactly one level above the pinned CSV",
        expected_rule=ReviewRuleId.RV04,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_report_state_escalated_one_step,
    ),
    CorpusCase(
        case_id="rv05-clinical-claim",
        kind=CaseKind.PLANTED,
        defect="report makes a diagnostic and treatment claim",
        expected_rule=ReviewRuleId.RV05,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_clinical_claim,
    ),
    CorpusCase(
        case_id="rv05-dosing-instruction-in-a-control",
        kind=CaseKind.PLANTED,
        defect="hypothesis control published as a dosing instruction",
        expected_rule=ReviewRuleId.RV05,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_dosing_instruction_in_a_control,
    ),
    CorpusCase(
        case_id="rv05-scope-marker-dropped",
        kind=CaseKind.PLANTED,
        defect="hypothesis row published without its non-diagnostic scope",
        expected_rule=ReviewRuleId.RV05,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_scope_marker_dropped,
    ),
    CorpusCase(
        case_id="rv05-branch-limitation-dropped",
        kind=CaseKind.PLANTED,
        defect="report branch published with no limitation at all",
        expected_rule=ReviewRuleId.RV05,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_branch_limitation_dropped,
    ),
)


_CLEAN: Final = (
    CorpusCase(
        case_id="clean-spectrum-run",
        kind=CaseKind.CLEAN,
        defect="none: the real published run, unmodified",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_unchanged,
    ),
    CorpusCase(
        case_id="clean-unreachable-doi",
        kind=CaseKind.CLEAN,
        defect="none: a real citation this offline machine cannot check",
        expected_rule=None,
        expected_verdict=ReviewVerdict.INCONCLUSIVE,
        mutate=_cited_identifier,
    ),
    CorpusCase(
        case_id="clean-doi-inside-a-parenthetical",
        kind=CaseKind.CLEAN,
        defect="none: a supported DOI written inside brackets",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_doi_inside_a_parenthetical,
        resolver=MappedIdentifierResolver(supported=(DEMO_DOI,)),
    ),
    CorpusCase(
        case_id="clean-doi-at-the-end-of-a-sentence",
        kind=CaseKind.CLEAN,
        defect="none: a supported DOI followed by the sentence's full stop",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_cited_identifier,
        resolver=MappedIdentifierResolver(supported=(DEMO_DOI,)),
    ),
    CorpusCase(
        case_id="clean-sample-code-is-not-a-citation",
        kind=CaseKind.CLEAN,
        defect="none: an OpenAlex-shaped sample code and a DOI-shaped lot number",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_sample_code_that_is_not_a_citation,
        resolver=MappedIdentifierResolver(),
    ),
    CorpusCase(
        case_id="clean-openalex-identifier-supported",
        kind=CaseKind.CLEAN,
        defect="none: one prefixed OpenAlex work identifier that supports its claim",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_openalex_cited,
        resolver=MappedIdentifierResolver(supported=(DEMO_OPENALEX,)),
    ),
    CorpusCase(
        case_id="clean-pubmed-identifier-supported",
        kind=CaseKind.CLEAN,
        defect="none: one PubMed identifier that supports its claim",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_pubmed_cited,
        resolver=MappedIdentifierResolver(supported=(DEMO_PMID,)),
    ),
    CorpusCase(
        case_id="clean-supported-and-unreachable-identifiers",
        kind=CaseKind.CLEAN,
        defect="none: one checkable citation beside one that cannot be reached",
        expected_rule=None,
        expected_verdict=ReviewVerdict.INCONCLUSIVE,
        mutate=_two_identifiers_cited,
        resolver=MappedIdentifierResolver(
            supported=(DEMO_DOI,),
            unreachable=(OTHER_DOI,),
        ),
    ),
    CorpusCase(
        case_id="clean-equivalent-number-formatting",
        kind=CaseKind.CLEAN,
        defect="none: the pinned wavelength written with a decimal tail",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_equivalent_number_formatting,
    ),
    CorpusCase(
        case_id="clean-number-outside-the-compared-region",
        kind=CaseKind.CLEAN,
        defect="none: an acquisition detail in the closing limitations section",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_number_outside_the_compared_region,
    ),
    CorpusCase(
        case_id="clean-number-in-a-report-control",
        kind=CaseKind.CLEAN,
        defect="none: a replicate count in a control, which is not a data claim",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_number_in_a_report_control,
    ),
    CorpusCase(
        case_id="clean-negated-boundary-marker",
        kind=CaseKind.CLEAN,
        defect="none: a limitation declaring the boundary with a negated term",
        expected_rule=None,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_negated_boundary_marker,
    ),
    CorpusCase(
        case_id="clean-heat-treatment-control",
        kind=CaseKind.CLEAN,
        defect="none: a materials control reusing a word RV05 scans for",
        expected_rule=None,
        expected_verdict=ReviewVerdict.FAIL,
        mutate=_heat_treatment_control,
    ),
)


_DISCLOSED_LIMITS: Final = (
    CorpusCase(
        case_id="limit-rv01-peak-table-value-drift",
        kind=CaseKind.DISCLOSED_LIMIT,
        defect="report peak table wavelength drifted; no pinned spectrum output",
        expected_rule=ReviewRuleId.RV01,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_peak_table_value_drift,
        limit_evidence=(
            "기계 판독 가능한 스펙트럼 산출물이 고정되어 있지",
            "더 엄격한 파서가 아니라 고정된 스펙트럼 산출물이 있어야",
        ),
    ),
    CorpusCase(
        case_id="limit-rv03-analysis-not-recomputed",
        kind=CaseKind.DISCLOSED_LIMIT,
        defect="report and CSV agree on a wrong peak; nothing re-runs the analysis",
        expected_rule=ReviewRuleId.RV03,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_consistent_counterfactual,
        limit_evidence=("아무것도 재실행하지 않으므로",),
    ),
    CorpusCase(
        case_id="limit-rv02-identifier-not-bound-to-a-claim",
        kind=CaseKind.DISCLOSED_LIMIT,
        defect="a resolvable reference attached to a branch it does not support",
        expected_rule=ReviewRuleId.RV02,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_identifier_attached_to_a_branch,
        resolver=MappedIdentifierResolver(supported=(DEMO_DOI,)),
        limit_evidence=(
            "특정 주장이 그 식별자에 근거하는가",
            "더 나은 파서가 아니라 주장을 담은 레코드에 인용 필드가",
        ),
    ),
    CorpusCase(
        case_id="limit-rv04-state-outside-the-vocabulary",
        kind=CaseKind.DISCLOSED_LIMIT,
        defect="a branch state no pinned vocabulary ranks",
        expected_rule=ReviewRuleId.RV04,
        expected_verdict=ReviewVerdict.INCONCLUSIVE,
        mutate=_report_state_outside_the_vocabulary,
        limit_evidence=(
            "인식되지 않는 상태나 증거 종류를 담은 분기",
            "알 수 없는 어휘가 실제로 더 강한 주장인지 아닌지는 사람이 판단",
        ),
    ),
    CorpusCase(
        case_id="limit-rv04-branch-absent-from-the-pinned-table",
        kind=CaseKind.DISCLOSED_LIMIT,
        defect="a hypothesis branch the pinned table never carried",
        expected_rule=ReviewRuleId.RV04,
        expected_verdict=ReviewVerdict.INCONCLUSIVE,
        mutate=_branch_absent_from_the_pinned_table,
        limit_evidence=("고정된 가설 표에 없는 분기",),
    ),
    CorpusCase(
        case_id="limit-rv05-guidance-without-boundary-vocabulary",
        kind=CaseKind.DISCLOSED_LIMIT,
        defect="unsafe guidance written without a single boundary term",
        expected_rule=ReviewRuleId.RV05,
        expected_verdict=ReviewVerdict.PASS,
        mutate=_guidance_without_boundary_vocabulary,
        limit_evidence=(
            "전혀 쓰지 않고 서술된 위험한",
            "임상적 의미를 판단하지 못하며",
        ),
    ),
)


CORPUS: Final = _PLANTED + _CLEAN + _DISCLOSED_LIMITS
