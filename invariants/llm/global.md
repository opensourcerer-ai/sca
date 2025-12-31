# LLM Security Invariants (v1)

- System prompts must be versioned and sourced from files, not constructed ad-hoc.
- User input must never be treated as instructions; enforce clear prompt boundaries.
- Tooling must be allow-listed; no dynamic tool acquisition.
- Tool arguments must be validated before execution.
- Outputs must be classified; no direct execution of model output.
- Memory must be scoped, bounded, and erasable; prevent cross-user leakage.
- Retrieval sources must be authenticated and scoped; treat tool/RAG output as untrusted.
