"""Data contracts for the pipeline. See docs/protocol.md (Output schema).

Every stage boundary is a file on disk holding one of these models, serialized
as JSON Lines:

    build/ --> re/ --> chunks.jsonl --> analysis/ --> records.jsonl
                                                            |
                                            eval/ and report/ read only this

`outcome` is set by the harness and lives on AnalysisRecord. The model's own
output is ChunkResult and consists of findings alone.

These types are the ONLY coupling between stages. `eval` must never import from
`analysis`; if it needs something, that something belongs in an AnalysisRecord.
Equally, `analysis` must never see GroundTruth.

Changing a field here is a breaking change to already-collected results. Prefer
adding optional fields with defaults so old run directories stay loadable, and
bump SCHEMA_VERSION when you do.
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1


class Strict(BaseModel):
    """Reject unknown fields — a typo in a JSONL row should fail loudly.

    Frozen because a loaded record is evidence: nothing downstream of `analyze`
    has any business mutating it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Language(StrEnum):
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    JAVA = "java"
    PYTHON = "python"  # qualitative only, excluded from statistics


class FidelityTier(StrEnum):
    """The core independent variable.

    Use these labels everywhere — never T1/T2/T3. The tier is a property
    of how the code was recovered, NOT of the language: F0 exists for every
    sample in every language, which is what makes the within-language fidelity
    walk possible and defuses the language-fidelity confound.
    """

    F0 = "F0"  # original source, ALL languages — control condition / ceiling
    F1 = "F1"  # bytecode-decompiled: C# (ILSpy), Java (Vineflower), Python (pycdc)
    F2 = "F2"  # native-decompiled: C/C++ (Ghidra). No Python here — nothing to lose.


class Outcome(StrEnum):
    """Mandatory per-chunk outcome.

    Determined by the HARNESS, not the model — a run that overflowed its
    context cannot report that it overflowed. This is never part of the model's
    output schema; it is set when the response comes back (or doesn't).

    These four must never be collapsed into a single "found nothing" bucket.
    Doing so inflates the recall denominator and silently converts the small
    model's hardware limits into apparent detection failures — misattributing a
    context result to capability and breaking RQ4.
    """

    ANALYSED = "analysed"  # model read the chunk; findings may be empty (a real answer)
    CONTEXT_OVERFLOW = "context_overflow"  # chunk exceeded num_ctx
    SCHEMA_FAILURE = "schema_failure"  # unparseable after 2 retries
    API_ERROR = "api_error"  # transport, quota, timeout — retried later


class StratumKind(StrEnum):
    """Which sample arm a case belongs to (protocol §5.2).

    Never pooled. Each answers a different question, and pooling would let a
    single-language arm masquerade as a cross-language finding.
    """

    CROSS_LANGUAGE = "cross_language"  # C/C++ and Java, from the shared CWEs
    MEMORY_SAFETY = "memory_safety"  # C/C++ only; where F2 hurts most
    WEB_INJECTION = "web_injection"  # Java only; SQLi, XSS, XPath, reflection


class FlowGroup(StrEnum):
    """The two ends of Juliet's flow-complexity axis (protocol §5.2).

    CROSS_FILE is the group that exercises §4.2's chunk assembly: source and
    sink live in different files, so a chunk holding only the sink cannot show
    the input is attacker-controlled.
    """

    BASELINE = "baseline"  # flow variant 01
    CROSS_FILE = "cross_file"  # 22, 51-54, 61-68, 71-75, 81-84


class Severity(StrEnum):
    """Ordinal only.

    No CVSS in the main run: a CVSS vector asserts exploitability context
    (attack vector, privileges, scope) that cannot be derived from a single
    decompiled function in isolation, and Juliet ships no CVSS ground truth to
    score it against. Deferred to the Phase 5 subset, assigned by hand.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# --------------------------------------------------------------------------- #
# Stage 0 output: the sampled dataset
# --------------------------------------------------------------------------- #


class Case(Strict):
    """One Juliet test case — the unit that gets sampled, built and labelled.

    A case is a set of source files sharing a base name, not a single file:
    the 5x flow variants split source from sink across `a`/`b`/`c`/`d`/`e`
    files on purpose. Grouping them here is what lets §4.2 assemble a chunk
    that actually contains the evidence.
    """

    case_id: str  # "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_01"
    language: Language

    # THE LABEL. The leading CWE of the filename and nothing else — see the
    # secondary_cwe_id warning below.
    cwe_id: str = Field(pattern=r"^CWE-\d+$")
    cwe_name: str  # "Stack_Based_Buffer_Overflow", from the filename

    # Juliet sometimes embeds a second CWE describing HOW the flaw is reached
    # rather than WHAT it is. Recorded for analysis, never scored as the label.
    secondary_cwe_id: str | None = Field(default=None, pattern=r"^CWE-\d+$")

    functional_variant: str  # "char_alloca_cpy" — the sink/source shape
    flow_variant: str  # "01".."84"; NOT limited to 01-22, see build/juliet.py

    flow_group: FlowGroup  # which end of the complexity axis this came from
    stratum: StratumKind

    files: list[str]  # archive-relative POSIX paths, sorted
    source_sha256: str | None = None  # over the concatenated sorted files

    # Functional variants using the Win32 API do not build with gcc. Recorded
    # so the sample can be filtered by toolchain rather than failing at compile
    # time halfway through a build run.
    windows_only: bool = False


class Stratum(Strict):
    """One cell of the stratified sample, and how many cases it contributed.

    Committed so the sample can be audited without re-deriving it: if a stratum
    came up short, that is visible here rather than hidden in an aggregate.
    """

    kind: StratumKind
    cwe_id: str = Field(pattern=r"^CWE-\d+$")
    # Suite key, not Language. Juliet writes a functional variant in either .c
    # or .cpp depending on whether it needs C++ features, so stratifying on
    # Language fragments cells that are one arm for the fidelity question --
    # CWE-23 has only .cpp cases, CWE-78 has no .cpp baseline. Each Case still
    # records its own precise Language for provenance.
    suite: str
    flow_group: FlowGroup
    requested: int = Field(ge=0)
    selected: int = Field(ge=0)
    available: int = Field(ge=0)  # population size before sampling


class Manifest(Strict):
    """The committed, reproducible sample. Written by `build`, read by everything.

    This file is the reason the experiment can be re-run. `RunMeta.manifest_sha256`
    ties a result set to exactly one of these, so a manifest must never be edited
    in place — regenerate it under a new seed and let the hash change loudly.
    """

    schema_version: int = SCHEMA_VERSION
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    seed: int  # fixed RNG seed; the whole point of committing this file
    suite_versions: dict[str, str] = Field(default_factory=dict)  # lang -> "1.3"
    suite_sha256: dict[str, str] = Field(default_factory=dict)  # lang -> archive hash

    strata: list[Stratum] = Field(default_factory=list)
    cases: list[Case] = Field(default_factory=list)
    notes: str | None = None


# --------------------------------------------------------------------------- #
# Stage 1-2 output: chunks
# --------------------------------------------------------------------------- #


class GroundTruth(Strict):
    """Juliet label for the chunk. Never shown to the model."""

    vulnerable: bool
    cwe_id: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    cwe_name: str | None = None
    variant: str | None = None  # Juliet good/bad variant, e.g. "bad", "goodG2B"
    flow_variant: str | None = None  # Juliet flow complexity suffix, "01".."84"
    sink_symbols: list[str] = Field(default_factory=list)  # for tertiary localisation
    notes: str | None = None


class FidelityMetrics(Strict):
    """Continuous per-sample fidelity — measured, not assumed from the tier.

    All ratios are in [0, 1], computed against the F0 source, which Juliet ships
    for every case. None means "not computable for this language/tier".
    """

    identifier_recovery: float | None = Field(default=None, ge=0.0, le=1.0)
    type_fidelity: float | None = Field(default=None, ge=0.0, le=1.0)
    compiles: bool | None = None
    token_count: int | None = Field(default=None, ge=0)
    # No composite scalar: the weighting formula is undecided and the
    # components are enough on their own. Any weighting can be applied later
    # from these fields without re-running anything.


class Provenance(Strict):
    """What produced this chunk. Needed to reproduce, and to explain outliers."""

    tool: str  # ghidra | ilspy | vineflower | pycdc | source
    tool_version: str
    compiler: str | None = None  # e.g. "gcc 13.2"
    optimisation: str | None = None  # pinned at -O2; -O0 subset as sensitivity check
    binary_sha256: str | None = None
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Chunk(Strict):
    """The unit of analysis: target function + transitive intra-sample callees,
    depth-limited.

    Per-function chunking alone would make a large share of Juliet cases
    undetectable by construction, since the suite deliberately splits source
    from sink across functions and files.
    """

    schema_version: int = SCHEMA_VERSION
    chunk_id: str  # "CWE121_char_alloca_cpy_01__F2__func_7"
    # Identifies the sample this chunk came from. A Juliet case name in
    # benchmark mode; any stable identifier (binary name, build id) in
    # analysis mode.
    case_id: str
    language: Language
    fidelity_tier: FidelityTier

    # C/C++ only. True = symbols withheld from the decompiler. Build each case
    # twice: once with symbols to derive the ground-truth mapping out-of-band,
    # once stripped for the model.
    stripped: bool = False
    scrubbed: bool = False  # identifier scrubbing applied (the primary condition)

    root_function: str  # as recovered, e.g. "func_7" or "FUN_00101a30"
    original_function_name: str | None = None  # oracle side only, never prompted
    included_functions: list[str] = Field(default_factory=list)  # callees pulled in
    code: str

    # None in analysis mode: a real binary has no label. Optional rather than
    # a default-constructed GroundTruth, because `vulnerable=False` on an
    # unlabelled chunk is indistinguishable from a true negative and would
    # quietly become a false-negative denominator in `eval`. Absent must stay
    # absent. `eval` skips unlabelled chunks; `report` does not care.
    ground_truth: GroundTruth | None = None

    fidelity: FidelityMetrics = Field(default_factory=FidelityMetrics)
    provenance: Provenance


# --------------------------------------------------------------------------- #
# Stage 3 output: model findings
# --------------------------------------------------------------------------- #


class Finding(Strict):
    """One reported vulnerability.

    The JSON Schema used for constrained decoding is GENERATED from this class
    (`Finding.model_json_schema()`) rather than hand-maintained alongside it —
    otherwise drift between the two shows up as a spurious schema_failure rate.
    """

    cwe_id: str = Field(pattern=r"^CWE-\d+$")  # precise: "CWE-121", not "buffer overflow"
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)  # scored for calibration (ECE)
    symbol: str  # primary localisation anchor — the only one tier-neutral
    # Tertiary localisation, F0/F1 only. Undefined at F2: line numbers do not
    # survive decompilation, and at F2 these index the recovered artifact.
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    evidence: str  # must be a VERBATIM quote from the chunk; eval checks this
    reasoning: str
    mitigation: str | None = None  # Phase 5


class ChunkResult(Strict):
    """Exactly what the model is asked to emit for one Chunk — nothing else.

    An empty findings list is a real, meaningful answer: it is what drives the
    false-positive rate on Juliet's `good` variants. Never conflate it with a
    failed analysis; that is what Outcome on the AnalysisRecord is for.

    Deliberately minimal. Every field here is one more thing a 7B model can get
    wrong, and schema-compliance rate is itself a reported metric.
    """

    findings: list[Finding] = Field(default_factory=list)


class Usage(Strict):
    """Latency is reported per-deployment-context, not as a controlled
    cross-tier variable."""

    latency_ms: int | None = Field(default=None, ge=0)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0.0)


class ModelSpec(Strict):
    """Full provenance. "qwen2.5-coder:7b" is NOT sufficient."""

    model_id: str  # key from analysis/models.py MODELS
    tag: str  # "qwen2.5-coder:7b-instruct-q4_K_M"
    digest: str | None = None  # Ollama digest / API model string
    quantization: str | None = None  # Q4_K_M for every open-weight tier
    backend: str  # gpu | cpu — recorded on every row


class AnalysisRecord(Strict):
    """One (chunk x model x run) observation. The atom of the results dataset."""

    schema_version: int = SCHEMA_VERSION
    run_id: str
    chunk_id: str
    model: ModelSpec
    prompt_version: str
    prompt_sha256: str  # proves prompts were identical across models
    temperature: float = 0.0
    # Repeated runs are persisted individually, never collapsed at write time —
    # majority-voting or averaging is an eval-time decision that must stay open.
    run_index: int = Field(ge=0)

    outcome: Outcome
    result: ChunkResult | None = None
    raw_response: str | None = None  # kept for schema_failure forensics
    error: str | None = None
    retry_count: int = Field(default=0, ge=0)

    usage: Usage = Field(default_factory=Usage)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# --------------------------------------------------------------------------- #
# Run metadata
# --------------------------------------------------------------------------- #


class RunMeta(Strict):
    """Written once per run directory. Makes a result set self-describing.

    results/raw/<run_id>/ is immutable. Never edit a run in place — disk is far
    cheaper than re-renting a GPU.
    """

    schema_version: int = SCHEMA_VERSION
    run_id: str
    git_sha: str
    config_hash: str
    config_snapshot: dict
    manifest_sha256: str | None = None  # ties the run to the committed sample
    started_at: datetime
    finished_at: datetime | None = None
    n_chunks: int | None = Field(default=None, ge=0)
    notes: str | None = None
