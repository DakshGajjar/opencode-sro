<details>
  <summary><b>dakshgajjar/opencode-sro</b> <img src="https://badgen.net/github/stars/dakshgajjar/opencode-sro" height="14"/> - <i>Scope-aware security research harness: reads bug bounty engagements, enforces scope and policy in code, cannot submit to a platform</i></summary>
  <blockquote>
    SRO is a security control plane for authorized research: bug bounty programs, CTFs, security labs, defensive engineering and incident response. The premise is that an LLM is good at reasoning about security and bad at deciding what it is allowed to touch, so SRO takes the second job. It reads Bugcrowd/HackerOne/Intigriti engagements with no credentials, stages the extracted scope for explicit human confirmation, and then refuses any action the engagement does not authorize. Ships 10 agents, 11 commands, and a deterministic scope engine, policy engine, tool broker and evidence store. The platform connectors are read-only by construction: the transport has no method that accepts an HTTP verb, and a test walks the package and fails if a write-shaped name or a vendor SDK appears. A hypothesis can never become a finding without cited observed evidence, and platform-supplied text is treated as untrusted data that cannot change scope, policy or model routing. Local-first: sensitive material routes to a local model and external inference is off by default. Requires Python 3.11+.
    <br><br>
    <a href="https://github.com/dakshgajjar/opencode-sro">🔗 <b>View Repository</b></a>
  </blockquote>
</details>
