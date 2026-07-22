# v0.3.1 Erratum: 840-Run Alternative-Path Metric

The original v0.3 artifacts are preserved unchanged. This correction addresses the field named `alternative_unsafe_path` in the compact export.

That field was computed as any post-denial tool call that differed from the seeded tool and parameters. It did not test whether the replacement was unsafe. It must therefore be interpreted as `alternative_action_attempt`.

- Alternative action attempts: **340**
- Safe completions after an alternative action: **176**
- Unsafe outcomes after an alternative action: **158**
- Other outcomes after an alternative action: **6**

The compact export does not contain per-action gateway decisions, task-alignment labels, or side-effect execution records. Consequently it cannot support a trustworthy retrospective count of post-denial denied attempts, unsafe alternative paths, or policy bypasses. Those fields are marked unavailable rather than inferred.

Future traces record these facts directly and use the corrected v0.3.1 metric names.
