"""The security kit's analysis provider: deterministic readings of retained security sources.

Interfaces: ``security.kev-catalog`` (KEV triage), ``security.kev-attention``
(KEV inbox attention), ``security.epss-scores`` (EPSS triage),
``security.cyclonedx-components`` (SBOM import), ``security.osv-applicability``
and ``security.cve-applicability`` (applicability assessments). No network, no
clock: every output is a function of the input.
"""

from __future__ import annotations

__version__ = "1.0.2"
