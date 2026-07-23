# AI Scientist roundtable product input

- Status: product-discovery input, not normative by itself
- Source: Korean Academy of Science and Technology 253rd roundtable, eight supplied session transcripts
- Applied: 2026-07-14
- Normative authority after adoption: `requirements.yaml` and `SPEC-v0.4.md`

## Source-quality boundary

All eight files state that they were produced with automatic transcription and that numbers and technical terms should be checked against the original material. This project therefore adopts repeated workflow principles, not unverified statistics, names, standards, or performance claims. Long merged paragraphs and obvious repetition in the Q&A are not treated as exact quotations or speaker-level legal positions.

The supplied discovery inputs are pinned by SHA-256 so the derivation can be reproduced without copying potentially inaccurate transcripts into the normative specification:

The protected source archive is resolved outside the repository through the
required `AI_SCIENTIST_TRANSCRIPT_DIR` locator. The repository records neither a
machine-specific absolute path nor a fallback copy. Verify the exact eight inputs
before reviewing this adoption record:

```sh
cd "$AI_SCIENTIST_TRANSCRIPT_DIR"
shasum -a 256 01_오프닝_조성배.md 02_주제발표1_유용균.md 03_주제발표2_이제현.md 04_주제발표3_이상민.md 05_지정토론1_손영성.md 06_지정토론2_김소영.md 07_지정토론3_양훼영.md 08_종합토론_QA.md
```

The hashes below were reverified against that protected locator on 2026-07-15.

| Session file | SHA-256 |
|---|---|
| `01_오프닝_조성배.md` | `baf78aa3ff3e47fa194e48735821e56ca7590a62ac893aa222475baf74a4b725` |
| `02_주제발표1_유용균.md` | `c2b06f5ffdd9183c62b943a709b90460726e0f0e58699ec4ba50e25d1d6a7189` |
| `03_주제발표2_이제현.md` | `0c480dd2a19eae103d51dce76c6a268789e611f1f43937dd151f941e3dfc6c8e` |
| `04_주제발표3_이상민.md` | `6976049c6d5a5e84fdc24914323e1554bd4b46470daa34b8a466661242e3cfba` |
| `05_지정토론1_손영성.md` | `346ad07d2829ed8b076918f652a82f1623693167d94aea8830ea8e74c83926cf` |
| `06_지정토론2_김소영.md` | `2a1c3addde75e5b9e5066cb5ada88e3438cac3170a7cd672aad91d69971c686b` |
| `07_지정토론3_양훼영.md` | `af66fdc7771deed7db4c1c39e15c725da0abb03fc14b9a735ad8922313043a6d` |
| `08_종합토론_QA.md` | `1a1b4a06c4c5ce565bb11cc5ec50ed936662381418f1278b7e73aa46565cec6a` |

## Adopted now

| Product rule | Transcript support | Concrete project mapping |
|---|---|---|
| A human-owned, why-first research intent precedes execution. | `01_오프닝_조성배.md:31-39`; `04_주제발표3_이상민.md:139-145`; `06_지정토론2_김소영.md:21-27`; `07_지정토론3_양훼영.md:23-25`; `08_종합토론_QA.md:27-35` | `ResearchIntent` requires a question, rationale, intended benefit, success criteria, constraints, and stop conditions. Its canonical digest is part of ActionPlan approval, provenance, projection, and export. |
| AI authority and research mode must be explicit. | `01_오프닝_조성배.md:19-31`; `02_주제발표1_유용균.md:79-85` | Each intent declares `ai_for_science`, `copilot`, or `bounded_agentic`. The current dry-lab remains approval-gated and cannot silently become fully autonomous. |
| Domain and real-world validation intent, including stop points, must be declared before execution. | `02_주제발표1_유용균.md:87-97`; `03_주제발표2_이제현.md:29-35,49-65,85-103`; `04_주제발표3_이상민.md:139-145` | Success criteria, constraints, and stop conditions are mandatory non-empty lists and are pinned into the intent digest. This increment does not claim to execute a domain validator; qualified validation-result evidence remains `AI-SCI-FUTURE-04`. Missing declarations or unsafe boundaries remain fail-closed. |
| Real, synthetic, and mixed data remain distinguishable, with distinct generator and validator responsibilities declared. | `08_종합토론_QA.md:41-51` | `data_origin` is mandatory. Synthetic or mixed data requires different generator and validator references. The references prove declared separation, not independent execution; that evidence remains `AI-SCI-FUTURE-04`. No fixed safe mixture ratio is encoded. |
| Scientific legitimacy depends on process, evidence, reproducibility, and accountable human decisions. | `01_오프닝_조성배.md:33-39`; `03_주제발표2_이제현.md:91-103,185-193`; `07_지정토론3_양훼영.md:25-31`; `08_종합토론_QA.md:27-39,77-79` | Existing immutable Artifact, persisted Review, one-use approval, and Export provenance contracts are retained. The intent digest connects the scientific purpose to those records. |

## Accepted for later planned increments

- `AI-SCI-FUTURE-01`: Claim maturity (`candidate`, `unverified`, `verified`, `reproduced`, `rejected`) belongs in the resource-backed Review/Export work, not as a label over the current fixture.
- `AI-SCI-FUTURE-02`: Citation roles (`supports`, `disputes`, `method`, `cross-domain bridge`) belong in the PubMed/OpenAlex evidence graph and Reviewer rules.
- `AI-SCI-FUTURE-03`: AI/human contribution disclosure belongs in versioned provenance and communication/export packs; it must not leak prompts or secrets.
- `AI-SCI-FUTURE-04`: Domain-specific validation profiles, qualified evaluator identity, pinned validation-result evidence, multimodal evaluators, and physical-instrument provenance require separate schemas and qualification evidence.
- `AI-SCI-FUTURE-05`: Provider portability and sovereign/self-hosted execution remain compatible with the existing provider-neutral adapter contract and no-fallback rule, but are not inferred as a new required runtime from this discussion.

These identifiers are discovery-backlog anchors, not release requirements. Promotion requires a normative requirement ID, Given/When/Then acceptance criteria, and an owned implementation increment.

## Deferred or rejected

- Fully human-out-of-the-loop research, autonomous publication, AI self-acceptance, and unbounded self-improving code loops are rejected for the MVP.
- Physical wet-lab, robot, synthesis, therapeutic, vaccine, pathogen, and other irreversible execution is outside the non-clinical dry-lab scope.
- The transcript does not settle legal liability or IP ownership among researcher, institution, and vendor. The product records accountable human approvals and technical provenance without inventing a legal conclusion; AI/human contribution disclosure remains `AI-SCI-FUTURE-03`.
- No transcript anecdote, model benchmark, GPU-subsidy claim, synthetic-data ratio, or named standard is adopted as an SLO or release fact without primary-source verification.
- Mentioned technologies such as MCP, Skills, desktop tools, or particular models are examples, not mandatory architecture. Adapters remain capability-governed and protocol-neutral.

## Session coverage

1. `01_오프닝_조성배.md`: role distinctions, human questions, trust, reproducibility, ethics.
2. `02_주제발표1_유용균.md`: research loop, hypothesis iteration, orchestration, citations, experiment design.
3. `03_주제발표2_이제현.md`: dynamic checkpoints, stop failures, real-world validation, benchmark audits, irreversible-action risk.
4. `04_주제발표3_이상민.md`: domain constraints, validation design, human interpretation, concrete dry-lab collaboration.
5. `05_지정토론1_손영성.md`: multidisciplinary interfaces, researcher-as-PI, simulator-first workflows, measurable utility.
6. `06_지정토론2_김소영.md`: why-first value, whole-project understanding, education and motivation.
7. `07_지정토론3_양훼영.md`: accountability design, verification-centered communication, research meaning.
8. `08_종합토론_QA.md`: reproducibility, synthetic-data governance, accountability/privacy tension, IP disclosure, portability, domain variation.
