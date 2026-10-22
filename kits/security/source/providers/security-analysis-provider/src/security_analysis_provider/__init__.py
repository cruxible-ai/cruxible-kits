"""The security kit's analysis provider: deterministic readings of retained security sources.

Interfaces: ``security.kev-catalog`` (KEV triage), ``security.kev-attention``
(KEV inbox attention), ``security.epss-scores`` (EPSS triage),
``security.cyclonedx-components`` (SBOM import), ``security.osv-applicability``
and ``security.cve-applicability`` (applicability assessments),
``security.workflow-facts`` and ``security.registry-facts`` (the system model:
what a repository declares and what a registry serves), ``security.sarif-findings``
(first-party code findings from SARIF scans, keyed so every finder meets) and
``security.harden`` (the hardening questions in three states), and incident
response's ``security.runtime-inventory``, ``security.log-reads``,
``security.credential-state`` and ``security.respond`` (the five incident questions
in three states). No network, no clock: every output is a function of the input.
"""

from __future__ import annotations

__version__ = "1.3.0"
