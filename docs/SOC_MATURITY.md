# SOC-CMM SIEM implementation gate

TriSOC includes an evidence-backed implementation profile adapted from
**SOC-CMM 2.4.2 Basic**. A SIEM is not ready merely because its infrastructure
deployed successfully: the operating model, people, processes, technology, and
services must also be assessed.

The source workbook remains the authoritative questionnaire. Complete it with
the relevant stakeholders, retain the reviewed workbook or exported results as
evidence, and record its 27 aspect results in
[`examples/soc-maturity-assessment.yaml`](../examples/soc-maturity-assessment.yaml).
Technology and Services aspects require both a maturity score and a capability
score.

Run the maturity gate on its own:

```sh
trisoc maturity check examples/soc-maturity-assessment.yaml --output json
```

For a deployment decision, run the combined gate so log sources and SOC
maturity cannot be approved independently:

```sh
trisoc siem check \
  --log-sources examples/log-source-inventory.yaml \
  --maturity examples/soc-maturity-assessment.yaml \
  --at 2026-07-16T08:00:00Z \
  --output json
```

## What is enforced

- The exact model reference is `soc-cmm-basic@2.4.2`.
- All five domains and 27 aspects require a score and evidence.
- Maturity uses the workbook's continuous 0–5 scale and defaults to a target of
  3 (Defined).
- Capability uses the workbook's continuous 0–3 scale for Technology and
  Services and defaults to a target of 2 (Managed).
- An assessment may raise either target, but cannot lower the defaults.
- Every aspect must meet its target; a high average cannot hide a weak aspect.
- Forty-five Log Management and Log Monitoring implementation controls must
  pass with evidence, including source inventory, filtering, normalisation,
  retention, secure transport, access, recovery, parsing, correlation,
  integrations, detection, case workflow, and search.
- Missing scores, controls, or evidence are `incomplete`, never a pass.

The structured model is
[`internal/maturity/soc-cmm-basic-2.4.2.json`](../internal/maturity/soc-cmm-basic-2.4.2.json).
It intentionally records the domain/aspect result structure and SIEM controls,
not the workbook's presentation or formulas.

## Source workbook QA and attribution

The supplied SOC-CMM 2.4.2 Basic workbook (published 16 April 2026) was inspected
across all 43 worksheets. Its five domains, 27 aspects, levels, default targets,
and Log Management/Log Monitoring material were verified. When evaluated by the
artifact inspection runtime outside desktop Excel, 27 Index completion cells
returned `#VALUE!` and three Endpoint Monitoring guidance lookups returned
`#N/A`. TriSOC therefore does not execute or trust workbook formulas as a CI
gate; users review the workbook results and TriSOC independently validates the
recorded scores, completeness, thresholds, and evidence.

The adapted model is licensed under CC BY-SA 4.0. Full attribution and the list
of changes are in [`internal/maturity/NOTICE.md`](../internal/maturity/NOTICE.md).
SOC-CMM is not affiliated with or responsible for TriSOC.
