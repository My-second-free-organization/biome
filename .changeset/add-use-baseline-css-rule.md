---
"@biomejs/biome": minor
---

Added new lint rule `useBaseline` for CSS. The rule warns when CSS properties, property values, at-rules, media conditions, functions, or pseudo-selectors are not part of the configured [Baseline](https://developer.mozilla.org/en-US/docs/Glossary/Baseline/Compatibility) tier. Supports configuring the availability target (`"widely"`, `"newly"`, or a year), and per-category allow lists.
