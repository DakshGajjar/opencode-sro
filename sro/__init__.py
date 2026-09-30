"""SRO - Security Research Orchestrator.

A security-research control plane that plugs into OpenCode.

Design invariants enforced by this package (see tests/ and docs/):

1. No LLM decides authorization. Scope and policy are deterministic code.
2. Platform readers are dumb. They read, they return data. Nothing else.
3. The platform connector layer cannot perform writes. The capability does not
   exist in the code, it is not merely discouraged by prompts.
4. Platform content is untrusted data, never trusted instructions.
5. Hypotheses are not findings. Only the verifier can move a finding.
"""

__version__ = "0.1.0"

SRO_ROOT_MARKER = ".sro"
