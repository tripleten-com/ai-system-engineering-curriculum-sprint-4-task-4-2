# ModelProvider fidelity

The active adapter is an in-process deterministic emulation. From the Project 4 opening
checkpoint it imitates a hosted provider's wire shape rather than a parsed result: the worker
hands it a provider key at composition time, the request carries the reading, the handling note,
and the retrieved procedure excerpt, and the answer is one JSON document returned as raw text.
The worker parses the summary out of that text itself. The emulator waits for the configured
local latency and answers the same text for the same request, every time.

The answer repeats what the request carried. A handling note comes back verbatim in the summary,
and so does the first sentence of the procedure excerpt. That is the behavior of a summarising
model given that text, and it is the behavior this Project's controls are measured against; it
is not a claim about any hosted model's output.

It proves the application contract, asynchronous composition, deterministic tests, and local
telemetry behavior. It does not prove hosted-model availability, output quality, token
accounting, safety behavior, provider throttling, network failure behavior, authentication
against a provider, or cost. The key it is given is checked by nothing at this checkpoint. No
live endpoint or credential is used. The fixed delay is not a performance measurement, capacity
test, latency target, or availability claim.
