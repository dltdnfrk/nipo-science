"""Persisted, trace-only Reviewer over pinned Artifact Versions.

The Reviewer implements RV01-RV05 against evidence that is already pinned. It
traces; it never recomputes. A correction is made by the producing path as a
new execution and a new Version, followed by a new Review. Nothing here
corrects, retries, or re-renders anything.

Structural incapability
-----------------------
The specification requires the capability to execute code or write an Artifact
to be *absent from the interface*, not merely unused. That is achieved here by
what this module is given rather than by what it declines to do.

`Reviewer` is constructed from a `PinnedRunEvidence` snapshot and an
`IdentifierResolver`. The snapshot is inert data -- records, digests, and bytes
-- captured by `LocalArtifactStore.pinned_run_evidence` on the other side of
the boundary. It holds no connection, no store, no service, no watcher, and no
callable, so no ordinary attribute path from a `Reviewer` instance reaches a
method that could commit a Version, append a Run output, publish a blob, or
start an execution. The absence is a property of the object graph, not a
convention.

The module reinforces that at its own import surface. It imports no runner, no
service, no store class, no subprocess, socket, or URL machinery, and no
dynamic-import or evaluation facility. From `nipo_local.store` it imports data
declarations only. `test_reviewer.py` proves both halves: it walks the source
tree of this module for a forbidden import or call, and it walks the reachable
attribute graph of a live `Reviewer` for a forbidden method.

Persistence is deliberately somewhere else. `Reviewer.review` returns findings;
`LocalArtifactStore.submit_review_findings` records them exactly once. The
Reviewer therefore does not hold, and cannot obtain, the object that writes.

Offline is not a failure
------------------------
`OfflineIdentifierResolver` is the default and resolves nothing, because a
local workbench has no guaranteed network and this module has no way to open
one. Every identifier it is asked about is `UNREACHABLE`, which RV02 requires
be recorded as `inconclusive` -- never `pass`, and never a false `fail`. An
`inconclusive` verdict reached this way is a correct outcome and must not be
scored against a false-positive budget.

What each rule can actually see
-------------------------------
RV01 compares numeric claims in the narrative report against the pinned
hypothesis CSV, which is the machine-readable execution output for those
claims, and cross-checks the report's declared peak count against its own
pinned peak table. The spectrum's per-peak values are published only inside
the narrative report: no pinned machine-readable spectrum output exists, so
those specific numbers can be checked for internal consistency but cannot be
traced to an independent pinned artifact. That limit is disclosed here rather
than papered over with a check that would only be measuring the report against
itself.

RV02 has no structured citation to read. Nothing in the current data model --
not `ResearchIntent`, not `EvidenceRecord`, not the evidence ledger -- carries
a bibliographic identifier or binds one to a specific claim. Identifiers are
therefore recovered by scanning the pinned report text, which means RV02 can
establish only that *some* cited identifier is or is not resolvable, never
that a *particular* claim rests on it. Half of the rule -- "and supports its
claim" -- is delegated to the resolver, because the pinned evidence contains
no claim-to-identifier link for the Reviewer to check. Closing that gap needs
a citation field on the record that makes the claim, not a better parser.

RV05 is a lexical boundary scan and its error is two-sided. It misses harmful
guidance written without the vocabulary, and it flags legitimate uses of that
vocabulary -- "heat treatment" on a reference coupon -- because it has no way
to read context. Only the first half used to be disclosed. Both are now in
`RULE_COVERAGE`, and the second is where this Reviewer's measured
false-positive rate comes from.

`RULE_COVERAGE` is measured, not decorative
-------------------------------------------
Every entry here is scored by `tests/review_corpus.py`. A defect the corpus
plants inside a rule's declared `checks` must be caught, and a defect the
corpus plants inside a rule's declared `limits` must *not* be, or the limit is
overstated and the disclosure is wrong. Writing a broader claim into `checks`
than the code can honour therefore fails the suite rather than shipping.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, Final, Protocol, final, override

from pydantic import BaseModel, ConfigDict, Field

from .store import (
    ContentState,
    FindingStatus,
    PinnedOutput,
    PinnedRunEvidence,
    ReviewFindingRecord,
    ReviewRecord,
    ReviewRuleId,
    ReviewSubmission,
    ReviewVerdict,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from datetime import datetime
    from uuid import UUID

CSV_ROLE: Final = "csv"
PNG_ROLE: Final = "png"
MARKDOWN_ROLE: Final = "markdown"
LEDGER_ROLE: Final = "ledger"

FINDING_ID_COUNT: Final = "one finding identifier is required per finding"

# Verdict precedence used to summarize one Review. `INCONCLUSIVE` outranks
# `PASS` so a Review that could not check something never reports as passed.
_VERDICT_RANK: Final = {
    ReviewVerdict.PASS: 0,
    ReviewVerdict.INCONCLUSIVE: 1,
    ReviewVerdict.WARN: 2,
    ReviewVerdict.FAIL: 3,
}

_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_DIGEST_LINE = re.compile(r"^- Canonical digest: `([0-9a-f]{64})`$")
_BRANCH_HEADING = re.compile(r"^### (?P<branch>[a-z_]+) \((?P<state>[a-z_]+)\)$")
_PEAK_COUNT = re.compile(r"^- Peaks: (\d+)$")
_TABLE_ROW = re.compile(r"^\| -?\d")

# DOI and PubMed are matched on their own canonical shapes. OpenAlex work ids
# require an explicit prefix: a bare `W` followed by digits collides with
# ordinary text often enough to manufacture citations that were never made.
# The suffix must not end on punctuation: a DOI written inside a sentence would
# otherwise swallow the closing period and be checked as a different identifier.
# A DOI suffix may legitimately contain parentheses, so `(` and `)` stay in the
# character class and an unbalanced closer is removed afterwards by
# `_trimmed_suffix` rather than by narrowing the class.
_DOI = re.compile(r"\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]*[-_()/:A-Za-z0-9]")
_PMID = re.compile(r"\bPMID:\s*(\d{1,8})\b", re.IGNORECASE)
_OPENALEX = re.compile(r"(?:openalex\.org/|openalex:)(W\d{4,12})", re.IGNORECASE)

# The research-only boundary vocabulary is written once. `_BOUNDARY_TERMS`
# finds it and `_NEGATED_BOUNDARY_TERMS` finds the negated form of the same
# vocabulary, so the negation list can never fall behind the term list. An
# enumerated negation list did exactly that: it named `non_diagnostic` and
# `non-clinical` only, so the product's own `non-therapeutic` wording was read
# as a violation of the boundary it was declaring.
_BOUNDARY_VOCABULARY: Final = (
    r"diagnos\w*|patient\w*|clinical\w*|therap\w*|treatment\w*|"
    r"prescrib\w*|prescription\w*|dosage|dosing|medication\w*"
)

_BOUNDARY_TERMS = re.compile(rf"\b(?:{_BOUNDARY_VOCABULARY})\b", re.IGNORECASE)

# `non` joined by nothing, a hyphen, an underscore, or one space. Only the
# negated phrase is removed, so an unnegated term elsewhere in the same region
# is still found.
_NEGATED_BOUNDARY_TERMS = re.compile(
    rf"\bnon[-_ ]?(?:{_BOUNDARY_VOCABULARY})\b",
    re.IGNORECASE,
)

_SCOPE_MARKER: Final = "non_diagnostic"

# Hypothesis states and evidence kinds, ordered by how much they claim. RV04 is
# violated when a claim sits above the level of the source it rests on.
_STATE_LEVEL: Final = {"insufficient": 0, "plausible": 1, "observed": 2}
_EVIDENCE_LEVEL: Final = {"insufficient": 0, "derived_observation": 1}


class FindingCode(StrEnum):
    """Stable machine-readable reasons a rule reached its verdict.

    Findings are asserted on by this code, never by prose: a message can carry
    a path or a value, and a test that matches on message text is one rename
    away from passing for the wrong reason.
    """

    RV01_CLAIMS_SUPPORTED = "rv01_claims_supported"
    RV01_CLAIM_UNSUPPORTED = "rv01_claim_unsupported"
    RV01_NO_CLAIMS_PRESENT = "rv01_no_claims_present"
    RV01_EVIDENCE_UNAVAILABLE = "rv01_evidence_unavailable"

    RV02_IDENTIFIERS_SUPPORT_CLAIMS = "rv02_identifiers_support_claims"
    RV02_NO_IDENTIFIERS_CITED = "rv02_no_identifiers_cited"
    RV02_IDENTIFIER_UNSUPPORTED = "rv02_identifier_unsupported"
    RV02_IDENTIFIER_UNREACHABLE = "rv02_identifier_unreachable"
    RV02_EVIDENCE_UNAVAILABLE = "rv02_evidence_unavailable"

    RV03_CORRESPONDS = "rv03_corresponds"
    RV03_CONTENT_DIGEST_MISMATCH = "rv03_content_digest_mismatch"
    RV03_PROVENANCE_MISMATCH = "rv03_provenance_mismatch"
    RV03_LEDGER_MISMATCH = "rv03_ledger_mismatch"
    RV03_EVIDENCE_UNAVAILABLE = "rv03_evidence_unavailable"

    RV04_WITHIN_SOURCE_LEVEL = "rv04_within_source_level"
    RV04_EVIDENCE_LEVEL_ESCALATED = "rv04_evidence_level_escalated"
    RV04_STATE_UNDERSTATED = "rv04_state_understated"
    RV04_LEVEL_UNRANKABLE = "rv04_level_unrankable"
    RV04_EVIDENCE_UNAVAILABLE = "rv04_evidence_unavailable"

    RV05_WITHIN_LIMITS = "rv05_within_limits"
    RV05_CLINICAL_LANGUAGE = "rv05_clinical_language"
    RV05_SCOPE_MARKER_MISSING = "rv05_scope_marker_missing"
    RV05_EVIDENCE_UNAVAILABLE = "rv05_evidence_unavailable"


class IdentifierScheme(StrEnum):
    """Citation identifier namespaces the Reviewer recognizes."""

    DOI = "doi"
    PMID = "pmid"
    OPENALEX = "openalex"


class IdentifierResolution(StrEnum):
    """Closed outcomes of one identifier check.

    `UNREACHABLE` covers every reason the check could not be completed,
    including an offline machine, and RV02 requires it to become
    `inconclusive` rather than `pass` or a manufactured `fail`.
    """

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class CitedIdentifier:
    """One identifier found in pinned text, with the role that carried it."""

    scheme: IdentifierScheme
    value: str
    role: str


class IdentifierResolver(Protocol):
    """Answer whether one cited identifier resolves and supports its claim."""

    def resolve(self, identifier: CitedIdentifier) -> IdentifierResolution:
        """Return the resolution outcome for one cited identifier."""
        ...


@final
class OfflineIdentifierResolver(IdentifierResolver):
    """Resolve nothing, because this module cannot open a network connection.

    This is the default. It is honest rather than pessimistic: no identifier
    lookup is possible from here, so every answer is `UNREACHABLE` and RV02
    records `inconclusive`.
    """

    @override
    def resolve(self, identifier: CitedIdentifier) -> IdentifierResolution:
        """Report every identifier as unreachable from an offline machine."""
        del identifier
        return IdentifierResolution.UNREACHABLE


@dataclass(frozen=True, slots=True)
class RuleFinding:
    """One rule's verdict over the pinned evidence it was able to read."""

    rule_id: ReviewRuleId
    verdict: ReviewVerdict
    code: FindingCode
    detail: tuple[str, ...]
    artifact_version_ids: tuple[UUID, ...]
    execution_ids: tuple[UUID, ...]

    @property
    def message(self) -> str:
        """Render one non-secret, human-readable summary of this finding."""
        if not self.detail:
            return f"{self.rule_id.value} {self.code.value}"
        return f"{self.rule_id.value} {self.code.value}: {'; '.join(self.detail)}"


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    """Every rule's finding for one Review, plus the summary verdict."""

    findings: tuple[RuleFinding, ...]

    @property
    def verdict(self) -> ReviewVerdict:
        """Return the highest-precedence verdict any rule reached."""
        return summary_verdict(item.verdict for item in self.findings)


def summary_verdict(verdicts: Iterable[ReviewVerdict]) -> ReviewVerdict:
    """Return the highest-precedence verdict across one Review's findings.

    Exposed because a reader that loads findings back from the store must
    summarize them by the same rule the Reviewer used, rather than reimplement
    the precedence and get `PASS` where the Reviewer would have said
    `INCONCLUSIVE`. An empty Review summarizes as `INCONCLUSIVE`, never
    `PASS`: nothing was checked, so nothing passed.
    """
    return max(
        verdicts,
        key=lambda value: _VERDICT_RANK[value],
        default=ReviewVerdict.INCONCLUSIVE,
    )


@dataclass(frozen=True, slots=True)
class RuleCoverage:
    """What one review rule establishes, and what it structurally cannot.

    `limits` is not a caveat bolted on for a screen: it is the disclosure this
    module's docstring already makes, in a form a surface can render, so a
    researcher reading a verdict sees the boundary of that verdict instead of
    inferring coverage the Reviewer never had. A surface that dropped these
    would be presenting a narrow check as a broad one.
    """

    rule_id: ReviewRuleId
    statement: str
    checks: tuple[str, ...]
    limits: tuple[str, ...]


RULE_COVERAGE: Final = (
    RuleCoverage(
        rule_id=ReviewRuleId.RV01,
        statement=(
            "모든 수치 주장이 고정된 실행 산출물 또는 고정된 원본 증거에 존재한다."
        ),
        checks=(
            "서술 보고서의 수치를 고정된 가설 CSV와 대조합니다. 그 CSV가 해당 "
            "주장들에 대한 기계 판독 가능한 실행 산출물입니다.",
            "보고서가 선언한 피크 개수를 같은 보고서가 고정한 피크 표와 "
            "교차 확인합니다.",
        ),
        limits=(
            "스펙트럼의 피크별 파장·보정 강도·돌출도 값은 서술 보고서 안에만 "
            "실려 있습니다. 기계 판독 가능한 스펙트럼 산출물이 고정되어 있지 "
            "않으므로, 이 값들은 보고서 내부 일관성까지만 확인되며 독립된 "
            "고정 아티팩트로 추적할 수 없습니다.",
            "이 공백은 더 엄격한 파서가 아니라 고정된 스펙트럼 산출물이 있어야 "
            "닫힙니다.",
        ),
    ),
    RuleCoverage(
        rule_id=ReviewRuleId.RV02,
        statement=(
            "인용된 모든 식별자가 해석되고 그 주장을 뒷받침한다. 확인할 수 없는 "
            "식별자는 통과가 아니라 판정 보류다."
        ),
        checks=(
            "고정된 보고서 본문을 훑어 DOI·PMID·OpenAlex 식별자를 수집합니다.",
            "문장이 붙여 준 마침표와 짝이 맞지 않는 닫는 괄호는 떼어 냅니다. "
            "인용되지 않은 값을 해석기에 묻는 것은 아무것도 묻지 않는 것보다 "
            "나쁘기 때문입니다.",
            "수집한 각 식별자를 설정된 해석기에 묻습니다.",
        ),
        limits=(
            "현재 데이터 모델의 어디에도 — ResearchIntent에도, EvidenceRecord "
            "에도, 증거 원장에도 — 서지 식별자를 특정 주장에 묶는 필드가 "
            "없습니다. 따라서 이 규칙은 '인용된 어떤 식별자가 해석되는가'까지만 "
            "말할 수 있고, '특정 주장이 그 식별자에 근거하는가'는 말할 수 "
            "없습니다.",
            "기본 해석기는 오프라인이며 모든 식별자를 도달 불가로 답합니다. "
            "그 결과인 판정 보류는 리뷰어의 실패가 아니라 올바른 결과입니다.",
            "이 공백은 더 나은 파서가 아니라 주장을 담은 레코드에 인용 필드가 "
            "있어야 닫힙니다.",
        ),
    ),
    RuleCoverage(
        rule_id=ReviewRuleId.RV03,
        statement="표와 그림이 고정된 입력·코드·산출물 다이제스트와 대응한다.",
        checks=(
            "고정된 각 버전의 저장된 바이트를 실행 기록이 남긴 다이제스트와 "
            "버전 행이 기록한 다이제스트 양쪽 모두와 대조합니다.",
            "증거 원장의 산출물 항목을 실제로 커밋된 버전과 대조합니다. "
            "체크섬·버전 식별자·버전 번호·바이트 크기·미디어 타입이 모두 "
            "비교 대상입니다.",
            "원장이 아예 누락한 산출물도 보고합니다. 원장은 자기 자신을 "
            "싣지 않으므로 원장 역할만 제외합니다.",
            "원장과 보고서가 담은 출처 다이제스트를 생성 실행 자신의 기록과 "
            "대조합니다. 격리 수준도 여기에 포함되므로 원장이 실행보다 강한 "
            "격리를 주장하면 불일치로 잡힙니다.",
        ),
        limits=(
            "대응 관계는 모두 이미 고정된 기록끼리만 확인합니다. 이 규칙은 "
            "아무것도 재실행하지 않으므로 분석이 옳았다고는 말할 수 없고, "
            "아티팩트가 그 실행이 만들었다고 주장하는 바로 그것이라는 사실까지만 "
            "말합니다.",
        ),
    ),
    RuleCoverage(
        rule_id=ReviewRuleId.RV04,
        statement="진술된 증거 수준이 실제로 확보한 수준을 넘지 않는다.",
        checks=(
            "각 가설 분기의 진술 상태를 원장이 그 분기에 기록한 증거 종류와 "
            "대조합니다.",
            "실제보다 높게 진술한 분기뿐 아니라 낮게 진술한 분기도 보고합니다.",
            "순위를 매길 수 없는 분기는 통과시키지 않고 판정 보류로 보고합니다.",
        ),
        limits=(
            "수준 비교는 과학 패키지가 기록하는 어휘 위에서만 이루어집니다. "
            "인식되지 않는 상태나 증거 종류를 담은 분기, 그리고 고정된 가설 "
            "표에 없는 분기는 순위를 매길 수 없으며, 안전하다고 가정하지 않고 "
            "판정 보류로 보고합니다.",
            "따라서 이 규칙은 어느 쪽이 옳은지 말하지 못합니다. 알 수 없는 "
            "어휘가 실제로 더 강한 주장인지 아닌지는 사람이 판단해야 합니다.",
        ),
    ),
    RuleCoverage(
        rule_id=ReviewRuleId.RV05,
        statement="산출물이 연구 전용·비임상·안전 한계를 지킨다.",
        checks=(
            "고정된 보고서와 가설 표에서 임상·진단·치료·투약 표현을 훑습니다.",
            "부정형은 경계 어휘 자체에서 파생되므로 non-diagnostic이든 "
            "non-therapeutic이든 제품 자신의 안전 표지는 위반으로 읽히지 "
            "않습니다.",
            "필수 연구 전용 범위 표지가 있는지 확인합니다.",
        ),
        limits=(
            "이것은 고정된 텍스트에 대한 어휘 수준의 경계 검사입니다. 임상적 "
            "의미를 판단하지 못하며, 이 표현들을 전혀 쓰지 않고 서술된 위험한 "
            "안내는 잡아내지 못합니다.",
            "반대 방향의 한계도 같이 공개합니다. 어휘 일치는 문맥을 모르므로 "
            "'열처리(heat treatment)'처럼 임상과 무관한 정당한 용법도 위반으로 "
            "보고합니다. 측정된 거짓 양성은 이 규칙에서 나옵니다.",
        ),
    ),
)
"""Per-rule coverage, published so no surface can imply more than was checked."""


class _LedgerModel(BaseModel):
    """Shared frozen projection of one pinned evidence-ledger document."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="ignore")


class LedgerOutput(_LedgerModel):
    """One output entry the pinned evidence ledger claims it published."""

    role: str
    name: str
    version_id: str
    version_no: int
    content_sha256: str
    media_type: str
    size_bytes: int


class LedgerEvidence(_LedgerModel):
    """One science evidence record the pinned ledger bound to a branch."""

    claim_id: str
    branch: str
    evidence_kind: str
    locator: str
    supporting_sha256: str


class EvidenceLedger(_LedgerModel):
    """The pinned evidence ledger, projected onto the fields RV03 and RV04 read."""

    ledger_schema: str = Field(alias="schema")
    code_sha256: str
    environment_sha256: str
    execution_isolation: str
    input_sha256: str
    producing_execution_id: str
    research_intent_sha256: str
    outputs: tuple[LedgerOutput, ...]
    science_evidence: tuple[LedgerEvidence, ...]


@dataclass(frozen=True, slots=True)
class ReportBranch:
    """One hypothesis branch block as the narrative report rendered it."""

    branch: str
    state: str
    observation: str
    limitation: str
    conclusion_scope: str


@dataclass(frozen=True, slots=True)
class ParsedReport:
    """The narrative report reduced to the claims a rule can actually check."""

    research_intent_sha256: str | None
    input_sha256: str | None
    branches: tuple[ReportBranch, ...]
    declared_peaks: int | None
    peak_rows: int
    limitations: tuple[str, ...]
    full_text: str


@dataclass(frozen=True, slots=True)
class TableRow:
    """One row of the pinned hypothesis table."""

    branch: str
    state: str
    observation: str
    control: str
    conclusion_scope: str


@dataclass(frozen=True, slots=True)
class _Evidence:
    """Everything one review pass parsed out of the pinned outputs once."""

    pinned: PinnedRunEvidence
    report: ParsedReport | None
    report_output: PinnedOutput | None
    table: tuple[TableRow, ...] | None
    table_output: PinnedOutput | None
    ledger: EvidenceLedger | None
    ledger_output: PinnedOutput | None


def parse_report(payload: bytes) -> ParsedReport | None:
    """Parse one pinned Markdown report, or None when it is not readable."""
    try:
        text = payload.decode()
    except UnicodeDecodeError:
        return None
    lines = text.split("\n")
    digests = [
        match.group(1) for match in map(_DIGEST_LINE.match, lines) if match is not None
    ]
    peaks = [match.group(1) for match in map(_PEAK_COUNT.match, lines) if match]
    return ParsedReport(
        research_intent_sha256=digests[0] if digests else None,
        input_sha256=digests[1] if len(digests) > 1 else None,
        branches=_report_branches(lines),
        declared_peaks=int(peaks[0]) if peaks else None,
        peak_rows=sum(1 for line in lines if _TABLE_ROW.match(line)),
        limitations=_limitation_bullets(lines),
        full_text=text,
    )


def parse_hypothesis_table(payload: bytes) -> tuple[TableRow, ...] | None:
    """Parse the pinned hypothesis CSV, or None when it is not readable."""
    try:
        text = payload.decode()
    except UnicodeDecodeError:
        return None
    rows = list(csv.reader(io.StringIO(text, newline="")))
    if not rows:
        return None
    expected = 5
    return tuple(
        TableRow(
            branch=row[0],
            state=row[1],
            observation=row[2],
            control=row[3],
            conclusion_scope=row[4],
        )
        for row in rows[1:]
        if len(row) == expected
    )


def parse_ledger(payload: bytes) -> EvidenceLedger | None:
    """Parse the pinned evidence ledger, or None when it is not readable."""
    try:
        return EvidenceLedger.model_validate_json(payload)
    except ValueError:
        return None


@final
class Reviewer:
    """Trace pinned evidence against RV01-RV05 without recomputing anything.

    Holds an inert evidence snapshot and a resolver. It has no store, no
    service, no runner, and no connection, so the capability to execute or to
    write an Artifact is absent from its object graph rather than declined at
    each call site.
    """

    __slots__ = ("_evidence", "_resolver")

    def __init__(
        self,
        evidence: PinnedRunEvidence,
        resolver: IdentifierResolver | None = None,
    ) -> None:
        """Bind one pinned evidence snapshot and its identifier resolver."""
        self._evidence = evidence
        self._resolver: IdentifierResolver = (
            OfflineIdentifierResolver() if resolver is None else resolver
        )

    def review(self) -> ReviewOutcome:
        """Evaluate every review rule over the pinned evidence exactly once."""
        parsed = self._parsed()
        return ReviewOutcome(
            findings=(
                _rule_rv01(parsed),
                _rule_rv02(parsed, self._resolver),
                _rule_rv03(parsed),
                _rule_rv04(parsed),
                _rule_rv05(parsed),
            )
        )

    def _parsed(self) -> _Evidence:
        """Decode each pinned output once so every rule reads the same bytes."""
        pinned = self._evidence
        report_output = _output(pinned, MARKDOWN_ROLE)
        table_output = _output(pinned, CSV_ROLE)
        ledger_output = _output(pinned, LEDGER_ROLE)
        return _Evidence(
            pinned=pinned,
            report=_apply(parse_report, report_output),
            report_output=report_output,
            table=_apply(parse_hypothesis_table, table_output),
            table_output=table_output,
            ledger=_apply(parse_ledger, ledger_output),
            ledger_output=ledger_output,
        )


def findings_submission(
    review: ReviewRecord,
    outcome: ReviewOutcome,
    finding_ids: Sequence[UUID],
    submitted_at: datetime,
) -> ReviewSubmission:
    """Bind one Review's findings to durable identities for a single submission.

    Identities arrive from the caller because minting them is not a Reviewer
    capability, and every finding is created `OPEN`: a Reviewer records what it
    found and never dispositions its own finding.
    """
    if len(finding_ids) != len(outcome.findings):
        raise ValueError(FINDING_ID_COUNT)
    return ReviewSubmission(
        review_id=review.id,
        submitted_at=submitted_at,
        findings=tuple(
            ReviewFindingRecord(
                id=identifier,
                org_id=review.org_id,
                project_id=review.project_id,
                review_id=review.id,
                sequence=index,
                rule_id=finding.rule_id,
                verdict=finding.verdict,
                status=FindingStatus.OPEN,
                code=finding.code.value,
                message=finding.message,
                artifact_version_ids=finding.artifact_version_ids,
                execution_ids=finding.execution_ids,
                created_at=submitted_at,
            )
            for index, (identifier, finding) in enumerate(
                zip(finding_ids, outcome.findings, strict=True), start=1
            )
        ),
    )


def _rule_rv01(evidence: _Evidence) -> RuleFinding:
    """Check every numeric claim against the pinned execution output."""
    report, table = evidence.report, evidence.table
    if report is None or table is None:
        return _finding(
            evidence,
            ReviewRuleId.RV01,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV01_EVIDENCE_UNAVAILABLE,
            _unavailable(evidence, (MARKDOWN_ROLE, CSV_ROLE)),
        )
    supported = {row.branch: _numbers(row.observation) for row in table}
    unsupported = [
        f"{item.branch}:{value}"
        for item in report.branches
        for value in sorted(
            _numbers(item.observation) - supported.get(item.branch, frozenset())
        )
    ]
    if report.declared_peaks is not None and report.declared_peaks != report.peak_rows:
        unsupported.append(f"peaks:{report.declared_peaks}!={report.peak_rows}")
    if unsupported:
        return _finding(
            evidence,
            ReviewRuleId.RV01,
            ReviewVerdict.FAIL,
            FindingCode.RV01_CLAIM_UNSUPPORTED,
            tuple(unsupported),
        )
    if not report.branches and report.declared_peaks is None:
        return _finding(
            evidence,
            ReviewRuleId.RV01,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV01_NO_CLAIMS_PRESENT,
            (),
        )
    return _finding(
        evidence,
        ReviewRuleId.RV01,
        ReviewVerdict.PASS,
        FindingCode.RV01_CLAIMS_SUPPORTED,
        (f"branches:{len(report.branches)}",),
    )


def _rule_rv02(evidence: _Evidence, resolver: IdentifierResolver) -> RuleFinding:
    """Check that every cited identifier resolves and supports its claim."""
    report = evidence.report
    if report is None:
        return _finding(
            evidence,
            ReviewRuleId.RV02,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV02_EVIDENCE_UNAVAILABLE,
            _unavailable(evidence, (MARKDOWN_ROLE,)),
        )
    cited = _identifiers(report.full_text, MARKDOWN_ROLE)
    if not cited:
        return _finding(
            evidence,
            ReviewRuleId.RV02,
            ReviewVerdict.PASS,
            FindingCode.RV02_NO_IDENTIFIERS_CITED,
            (),
        )
    resolved = {item: resolver.resolve(item) for item in cited}
    unsupported = _cited_labels(resolved, IdentifierResolution.UNSUPPORTED)
    if unsupported:
        return _finding(
            evidence,
            ReviewRuleId.RV02,
            ReviewVerdict.FAIL,
            FindingCode.RV02_IDENTIFIER_UNSUPPORTED,
            unsupported,
        )
    unreachable = _cited_labels(resolved, IdentifierResolution.UNREACHABLE)
    if unreachable:
        return _finding(
            evidence,
            ReviewRuleId.RV02,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV02_IDENTIFIER_UNREACHABLE,
            unreachable,
        )
    return _finding(
        evidence,
        ReviewRuleId.RV02,
        ReviewVerdict.PASS,
        FindingCode.RV02_IDENTIFIERS_SUPPORT_CLAIMS,
        tuple(sorted(f"{item.scheme.value}:{item.value}" for item in cited)),
    )


def _rule_rv03(evidence: _Evidence) -> RuleFinding:
    """Check every table and figure against its pinned code, input, and output."""
    pinned = evidence.pinned
    if not pinned.outputs:
        return _finding(
            evidence,
            ReviewRuleId.RV03,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV03_EVIDENCE_UNAVAILABLE,
            (),
        )
    mismatches: list[str] = []
    unavailable: list[str] = []
    for output in pinned.outputs:
        mismatches.extend(_content_mismatches(output))
        unavailable.extend(_content_unavailable(output))
    mismatches.extend(_execution_mismatches(pinned))
    if pinned.execution is None:
        unavailable.append("execution:absent")
    mismatches.extend(_ledger_mismatches(evidence))
    mismatches.extend(_report_provenance_mismatches(evidence))
    if mismatches:
        return _finding(
            evidence,
            ReviewRuleId.RV03,
            ReviewVerdict.FAIL,
            _rv03_code(mismatches),
            tuple(sorted(mismatches)),
        )
    if unavailable:
        return _finding(
            evidence,
            ReviewRuleId.RV03,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV03_EVIDENCE_UNAVAILABLE,
            tuple(sorted(unavailable)),
        )
    return _finding(
        evidence,
        ReviewRuleId.RV03,
        ReviewVerdict.PASS,
        FindingCode.RV03_CORRESPONDS,
        (f"outputs:{len(pinned.outputs)}",),
    )


def _rule_rv04(evidence: _Evidence) -> RuleFinding:
    """Check that no stated evidence level exceeds the level actually retrieved."""
    table, ledger, report = evidence.table, evidence.ledger, evidence.report
    if table is None or ledger is None or report is None:
        return _finding(
            evidence,
            ReviewRuleId.RV04,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV04_EVIDENCE_UNAVAILABLE,
            _unavailable(evidence, (CSV_ROLE, LEDGER_ROLE, MARKDOWN_ROLE)),
        )
    source = {row.branch: row.state for row in table}
    escalated = _escalations(ledger, report, source)
    unrankable = _unrankable(ledger, report, source)
    if escalated:
        return _finding(
            evidence,
            ReviewRuleId.RV04,
            ReviewVerdict.FAIL,
            FindingCode.RV04_EVIDENCE_LEVEL_ESCALATED,
            tuple(sorted(escalated)),
        )
    if unrankable:
        return _finding(
            evidence,
            ReviewRuleId.RV04,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV04_LEVEL_UNRANKABLE,
            tuple(sorted(unrankable)),
        )
    understated = _understatements(report, source)
    if understated:
        return _finding(
            evidence,
            ReviewRuleId.RV04,
            ReviewVerdict.WARN,
            FindingCode.RV04_STATE_UNDERSTATED,
            tuple(sorted(understated)),
        )
    return _finding(
        evidence,
        ReviewRuleId.RV04,
        ReviewVerdict.PASS,
        FindingCode.RV04_WITHIN_SOURCE_LEVEL,
        (f"branches:{len(source)}",),
    )


def _rule_rv05(evidence: _Evidence) -> RuleFinding:
    """Check that pinned output stays inside the research-only safety limits."""
    report, table = evidence.report, evidence.table
    if report is None or table is None:
        return _finding(
            evidence,
            ReviewRuleId.RV05,
            ReviewVerdict.INCONCLUSIVE,
            FindingCode.RV05_EVIDENCE_UNAVAILABLE,
            _unavailable(evidence, (MARKDOWN_ROLE, CSV_ROLE)),
        )
    breaches = sorted({term.lower() for term in _boundary_terms(report, table)})
    if breaches:
        return _finding(
            evidence,
            ReviewRuleId.RV05,
            ReviewVerdict.FAIL,
            FindingCode.RV05_CLINICAL_LANGUAGE,
            tuple(breaches),
        )
    missing = _missing_scope_markers(report, table)
    if missing:
        return _finding(
            evidence,
            ReviewRuleId.RV05,
            ReviewVerdict.FAIL,
            FindingCode.RV05_SCOPE_MARKER_MISSING,
            tuple(sorted(missing)),
        )
    return _finding(
        evidence,
        ReviewRuleId.RV05,
        ReviewVerdict.PASS,
        FindingCode.RV05_WITHIN_LIMITS,
        (f"rows:{len(table)}",),
    )


def _source_evidence_level(state: str) -> int:
    """Return the highest evidence level one retrieved branch state supports.

    A branch whose pinned state is `insufficient` retrieved nothing to derive
    an observation from, so an evidence record claiming `derived_observation`
    over it states more than was retrieved.
    """
    if state == "insufficient":
        return _EVIDENCE_LEVEL["insufficient"]
    return _EVIDENCE_LEVEL["derived_observation"]


def _rankable_state(branch: str, state: str, source: dict[str, str]) -> bool:
    """Return whether one branch state can be compared with its pinned source."""
    return branch in source and state in _STATE_LEVEL and source[branch] in _STATE_LEVEL


def _rankable_evidence(branch: str, kind: str, source: dict[str, str]) -> bool:
    """Return whether one evidence kind can be compared with its pinned source."""
    return (
        branch in source and kind in _EVIDENCE_LEVEL and source[branch] in _STATE_LEVEL
    )


def _unrankable(
    ledger: EvidenceLedger,
    report: ParsedReport,
    source: dict[str, str],
) -> list[str]:
    """Collect every claim whose level cannot be compared with its source.

    A vocabulary this rule does not know is not evidence of safety. Ranking an
    unrecognized evidence kind or branch state at zero silently treats the
    strongest possible claim as the weakest: a ledger deriving a
    `clinical_confirmation` was read as claiming nothing, and a report stating
    a branch as `confirmed` was reported as *understating* it. A branch the
    pinned table never carried cannot be ranked either, in the ledger or in
    the narrative. All of them are reported instead.
    """
    unrankable = [
        f"ledger:{record.branch}:{record.evidence_kind}"
        for record in ledger.science_evidence
        if not _rankable_evidence(record.branch, record.evidence_kind, source)
    ]
    unrankable.extend(
        f"report:{item.branch}:{item.state}"
        for item in report.branches
        if not _rankable_state(item.branch, item.state, source)
    )
    return unrankable


def _escalations(
    ledger: EvidenceLedger,
    report: ParsedReport,
    source: dict[str, str],
) -> list[str]:
    """Collect every claim sitting above the level of its retrieved source."""
    escalated = [
        f"ledger:{record.branch}:{record.evidence_kind}"
        for record in ledger.science_evidence
        if _rankable_evidence(record.branch, record.evidence_kind, source)
        and _EVIDENCE_LEVEL[record.evidence_kind]
        > _source_evidence_level(source[record.branch])
    ]
    escalated.extend(
        f"report:{item.branch}:{item.state}"
        for item in report.branches
        if _rankable_state(item.branch, item.state, source)
        and _STATE_LEVEL[item.state] > _STATE_LEVEL[source[item.branch]]
    )
    return escalated


def _understatements(report: ParsedReport, source: dict[str, str]) -> list[str]:
    """Collect branches the narrative states below their pinned source level."""
    return [
        f"report:{item.branch}:{item.state}"
        for item in report.branches
        if _rankable_state(item.branch, item.state, source)
        and _STATE_LEVEL[item.state] < _STATE_LEVEL[source[item.branch]]
    ]


def _boundary_terms(report: ParsedReport, table: tuple[TableRow, ...]) -> list[str]:
    """Collect research-only boundary terms found in claim-bearing text.

    The researcher's own intent text is excluded on purpose: a question that
    mentions a clinical context is not the system making a clinical claim, and
    flagging it would manufacture a false positive out of the input.
    """
    regions = [
        *(item.observation for item in report.branches),
        *(item.limitation for item in report.branches),
        *report.limitations,
        *(row.observation for row in table),
        *(row.control for row in table),
    ]
    return [
        match.group(0)
        for region in regions
        for match in _BOUNDARY_TERMS.finditer(_strip_negations(region))
    ]


def _missing_scope_markers(
    report: ParsedReport,
    table: tuple[TableRow, ...],
) -> list[str]:
    """Collect claims published without their non-diagnostic scope marker."""
    missing = [
        f"csv:{row.branch}" for row in table if row.conclusion_scope != _SCOPE_MARKER
    ]
    missing.extend(
        f"report:{item.branch}"
        for item in report.branches
        if item.conclusion_scope != _SCOPE_MARKER or not item.limitation
    )
    return missing


def _content_mismatches(output: PinnedOutput) -> list[str]:
    """Collect every way one pinned output disagrees with its own digests."""
    if output.content_state is ContentState.TAMPERED:
        return [f"{output.role}:content_digest"]
    version = output.version
    if version is None or output.content is None:
        return []
    mismatches: list[str] = []
    if version.content_sha256 != output.recorded_sha256:
        mismatches.append(f"{output.role}:run_output_digest")
    if hashlib.sha256(output.content).hexdigest() != version.content_sha256:
        mismatches.append(f"{output.role}:content_digest")
    if version.size_bytes != len(output.content):
        mismatches.append(f"{output.role}:size")
    return mismatches


def _content_unavailable(output: PinnedOutput) -> list[str]:
    """Report a pinned output whose bytes or Version row could not be read."""
    if output.content_state is ContentState.ABSENT or output.version is None:
        return [f"{output.role}:absent"]
    return []


def _execution_mismatches(pinned: PinnedRunEvidence) -> list[str]:
    """Collect every Version whose provenance disagrees with the execution."""
    execution = pinned.execution
    if execution is None:
        return []
    mismatches: list[str] = []
    for output in pinned.outputs:
        version = output.version
        if version is None:
            continue
        if version.producing_execution_id != execution.id:
            mismatches.append(f"{output.role}:producing_execution")
        if version.code_sha256 != execution.code_sha256:
            mismatches.append(f"{output.role}:code_sha256")
        if version.environment_sha256 != execution.environment_sha256:
            mismatches.append(f"{output.role}:environment_sha256")
    return mismatches


def _ledger_mismatches(evidence: _Evidence) -> list[str]:
    """Collect every disagreement between the pinned ledger and the Versions."""
    ledger = evidence.ledger
    if ledger is None:
        return []
    mismatches = _ledger_provenance_mismatches(evidence, ledger)
    published = {item.role: item for item in evidence.pinned.outputs}
    for entry in ledger.outputs:
        output = published.get(entry.role)
        if output is None or output.version is None:
            mismatches.append(f"ledger:{entry.role}:absent")
            continue
        version = output.version
        if entry.content_sha256 != version.content_sha256:
            mismatches.append(f"ledger:{entry.role}:content_sha256")
        if entry.version_id != str(version.id):
            mismatches.append(f"ledger:{entry.role}:version_id")
        if entry.version_no != version.version_no:
            mismatches.append(f"ledger:{entry.role}:version_no")
        if entry.size_bytes != version.size_bytes:
            mismatches.append(f"ledger:{entry.role}:size_bytes")
        if entry.media_type != version.media_type:
            mismatches.append(f"ledger:{entry.role}:media_type")
    mismatches.extend(_ledger_omissions(evidence, ledger))
    return mismatches


def _ledger_omissions(evidence: _Evidence, ledger: EvidenceLedger) -> list[str]:
    """Collect every published output the pinned ledger never listed.

    Comparing the ledger's entries against the Versions only catches a ledger
    that says something wrong. A ledger that says nothing at all about a
    published figure or table disagrees with the Versions just as much, and
    reading it would understate what the execution actually published.

    The ledger itself is excluded because it is the last output committed and
    cannot contain its own digest, so its absence from its own output list is
    the producer's shape rather than an omission.
    """
    listed = {entry.role for entry in ledger.outputs}
    return [
        f"ledger:{item.role}:unlisted"
        for item in evidence.pinned.outputs
        if item.role != LEDGER_ROLE and item.role not in listed
    ]


def _ledger_provenance_mismatches(
    evidence: _Evidence,
    ledger: EvidenceLedger,
) -> list[str]:
    """Collect ledger provenance fields disagreeing with the pinned execution."""
    execution = evidence.pinned.execution
    if execution is None:
        return []
    expected = {
        "code_sha256": (ledger.code_sha256, execution.code_sha256),
        "environment_sha256": (
            ledger.environment_sha256,
            execution.environment_sha256,
        ),
        "input_sha256": (ledger.input_sha256, execution.input_sha256),
        "research_intent_sha256": (
            ledger.research_intent_sha256,
            execution.research_intent_sha256,
        ),
        "producing_execution_id": (
            ledger.producing_execution_id,
            str(execution.id),
        ),
        "execution_isolation": (
            ledger.execution_isolation,
            execution.execution_isolation,
        ),
    }
    return [
        f"ledger:provenance:{field}"
        for field, (claimed, actual) in expected.items()
        if claimed != actual
    ]


def _report_provenance_mismatches(evidence: _Evidence) -> list[str]:
    """Collect report-declared digests disagreeing with the pinned execution."""
    report, execution = evidence.report, evidence.pinned.execution
    if report is None or execution is None:
        return []
    declared = {
        "research_intent_sha256": (
            report.research_intent_sha256,
            execution.research_intent_sha256,
        ),
        "input_sha256": (report.input_sha256, execution.input_sha256),
    }
    return [
        f"report:provenance:{field}"
        for field, (claimed, actual) in declared.items()
        if claimed is not None and claimed != actual
    ]


def _rv03_code(mismatches: list[str]) -> FindingCode:
    """Name the most specific RV03 defect present in one mismatch list."""
    if any(
        item.endswith(("content_digest", "size", "run_output_digest"))
        for item in mismatches
    ):
        return FindingCode.RV03_CONTENT_DIGEST_MISMATCH
    if any(item.startswith("ledger:") for item in mismatches):
        return FindingCode.RV03_LEDGER_MISMATCH
    return FindingCode.RV03_PROVENANCE_MISMATCH


def _trimmed_suffix(value: str) -> str:
    """Drop delimiters a DOI swallowed from the sentence that carried it.

    A DOI suffix may contain parentheses, so the pattern accepts them; a DOI
    written inside a parenthetical therefore ends up carrying the closing
    parenthesis of the parenthetical. Only an *unbalanced* closer is removed,
    which leaves `10.1/a(b)` intact, reduces `(10.1/a)` to `10.1/a`, and
    reduces `(10.1/a(b))` to `10.1/a(b)`. Asking a resolver about a value the
    author never cited is worse than asking about nothing: it turns a correct
    citation into an unsupported one.
    """
    trimmed = value
    while trimmed and (
        trimmed.endswith(".")
        or (trimmed.endswith(")") and trimmed.count(")") > trimmed.count("("))
    ):
        trimmed = trimmed[:-1]
    return trimmed


def _identifiers(text: str, role: str) -> tuple[CitedIdentifier, ...]:
    """Extract every DOI, PubMed, and OpenAlex identifier cited in one text."""
    found = [
        CitedIdentifier(
            scheme=IdentifierScheme.DOI,
            value=_trimmed_suffix(match.group(0)),
            role=role,
        )
        for match in _DOI.finditer(text)
    ]
    found.extend(
        CitedIdentifier(scheme=IdentifierScheme.PMID, value=match.group(1), role=role)
        for match in _PMID.finditer(text)
    )
    found.extend(
        CitedIdentifier(
            scheme=IdentifierScheme.OPENALEX,
            value=match.group(1).upper(),
            role=role,
        )
        for match in _OPENALEX.finditer(text)
    )
    return tuple(dict.fromkeys(found))


def _cited_labels(
    resolved: dict[CitedIdentifier, IdentifierResolution],
    outcome: IdentifierResolution,
) -> tuple[str, ...]:
    """Label every identifier that reached one resolution outcome."""
    return tuple(
        sorted(
            f"{item.scheme.value}:{item.value}"
            for item, value in resolved.items()
            if value is outcome
        )
    )


def _numbers(text: str) -> frozenset[Decimal]:
    """Extract numeric claims as exact decimal values, ignoring formatting."""
    values: set[Decimal] = set()
    for match in _NUMBER.finditer(text):
        try:
            values.add(Decimal(match.group(0)))
        except InvalidOperation:  # pragma: no cover - the pattern excludes this
            continue
    return frozenset(values)


def _strip_negations(text: str) -> str:
    """Remove any negated boundary phrase before the boundary scan.

    Negation is derived from the same vocabulary the scan uses, so declaring a
    limit -- `non_diagnostic`, `non-clinical`, `non-therapeutic` -- is never
    read as crossing it, while an unnegated term in the same sentence still is.
    """
    return _NEGATED_BOUNDARY_TERMS.sub(" ", text)


def _report_branches(lines: list[str]) -> tuple[ReportBranch, ...]:
    """Collect each rendered hypothesis branch block from the report lines."""
    branches: list[ReportBranch] = []
    current: dict[str, str] = {}
    for line in lines:
        heading = _BRANCH_HEADING.match(line)
        if heading is not None:
            _close_branch(branches, current)
            current = {
                "branch": heading.group("branch"),
                "state": heading.group("state"),
            }
        elif current:
            _absorb_branch_line(current, line)
    _close_branch(branches, current)
    return tuple(branches)


def _absorb_branch_line(current: dict[str, str], line: str) -> None:
    """Record one labelled bullet belonging to the open branch block."""
    labels = {
        "- Observation: ": "observation",
        "- Limitation: ": "limitation",
        "- Conclusion scope: ": "conclusion_scope",
    }
    for prefix, key in labels.items():
        if line.startswith(prefix):
            current[key] = line[len(prefix) :]
            return


def _close_branch(branches: list[ReportBranch], current: dict[str, str]) -> None:
    """Materialize the open branch block, if one was being collected."""
    if not current:
        return
    branches.append(
        ReportBranch(
            branch=current["branch"],
            state=current["state"],
            observation=current.get("observation", ""),
            limitation=current.get("limitation", ""),
            conclusion_scope=current.get("conclusion_scope", ""),
        )
    )


def _limitation_bullets(lines: list[str]) -> tuple[str, ...]:
    """Collect the report's closing limitations section bullets."""
    heading = "## Limitations"
    if heading not in lines:
        return ()
    tail = lines[lines.index(heading) + 1 :]
    return tuple(line[2:] for line in tail if line.startswith("- "))


def _output(pinned: PinnedRunEvidence, role: str) -> PinnedOutput | None:
    """Find the one pinned output published under a given chain role."""
    return next((item for item in pinned.outputs if item.role == role), None)


def _apply[ParsedT](
    parser: Callable[[bytes], ParsedT | None],
    output: PinnedOutput | None,
) -> ParsedT | None:
    """Parse one pinned output's bytes, or None when they were unavailable."""
    if output is None or output.content is None:
        return None
    return parser(output.content)


def _unavailable(evidence: _Evidence, roles: tuple[str, ...]) -> tuple[str, ...]:
    """Name each role a rule needed but could not read from pinned evidence."""
    published = {item.role: item for item in evidence.pinned.outputs}
    return tuple(
        f"{role}:{_content_label(published.get(role))}"
        for role in roles
        if role not in published or published[role].content is None
    )


def _content_label(output: PinnedOutput | None) -> str:
    """Name why one role's bytes were not available to a rule."""
    return "absent" if output is None else output.content_state.value


def _finding(
    evidence: _Evidence,
    rule_id: ReviewRuleId,
    verdict: ReviewVerdict,
    code: FindingCode,
    detail: tuple[str, ...],
) -> RuleFinding:
    """Build one finding pinned to the evidence the whole Review pinned."""
    return RuleFinding(
        rule_id=rule_id,
        verdict=verdict,
        code=code,
        detail=detail,
        artifact_version_ids=evidence.pinned.artifact_version_ids,
        execution_ids=evidence.pinned.execution_ids,
    )
