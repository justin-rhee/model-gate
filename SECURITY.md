# Security policy: model-gate

## Posture

model-gate is provided as-is, with no warranty (see LICENSE). It reduces what an agent can do with your model API key. It does not make the key safe on its own.

The containment holds only if the host enforces three things the gate can't check for you:

- the agent's user can't read the key file, write the state folder or the log, or become the gate's user
- the agent's user can't reach the provider's API directly, because a firewall rule or proxy blocks it
- nothing else on the machine hands the agent a key

If any of those fails, the gate still forwards and logs calls that come through it, but an agent can go around it.

What the gate guarantees by construction: the key is read from a file per call and added as a header, and headers are never passed to the log, so the key can't be written there. Any key the agent sends is dropped before forwarding.

Known limits: the cap is checked before each call, so a session can go over by one call's tokens. Token counts are read from the first 4 MB of a response. Only Anthropic's Messages API token fields are counted. Request and response bodies, when you turn them on, hold everything the agent said and was told, so keep that folder private.

## Validation status

The offline suite in `tests/test_model_gate.py` has been run: 16 tests, all passing, against a fake API on localhost. Four protections were each removed by hand to confirm the suite then fails: the closed-session check, dropping the agent's own key, the cap check, and reading streamed token counts. There is no adversarial corpus beyond those tests.

## Reporting a problem

Report privately through this repository's Security tab, using GitHub's "Report a vulnerability" flow, or open a minimal issue that describes the impact without a working exploit. Please give a reasonable window for a fix before publishing details.
