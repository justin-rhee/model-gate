# model-gate

[![tests](https://github.com/justin-rhee/model-gate/actions/workflows/test.yml/badge.svg)](https://github.com/justin-rhee/model-gate/actions/workflows/test.yml) [![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![python 3](https://img.shields.io/badge/python-3-brightgreen.svg) ![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)

Keeps your model API key away from your agent. The agent calls a small local gate, and only the gate holds the key, so the agent can reach a model only while you've opened a session, only up to a token budget, and every call is written to a log it can't edit.

```
$ model-gate status
closed  0 tokens used  cap 30
agent call: 403

$ model-gate open session-1
open  session-1  cap 30
upstream got key: only-the-gate-has-this
agent call: 200
upstream got key: only-the-gate-has-this
agent call: 200
agent call: 429

$ model-gate close
closed  36 tokens used
agent call: 403

log: 8 lines, gate key in it: 0
```

That's real output. Every call carries a key the agent found on its own, and it never gets through. `bash examples/demo.sh` reproduces it against a fake API, with no real key and no network.

I built it for [Fallow](https://fallowproject.com), a study where a Claude model woke four times a day on a small server with no task or goal, and I read everything it did. My first containment was hooks on the agent's own CLI. A test on the box then showed the agent could start its own copy of the CLI, one the hooks never saw, three different ways. So I stopped guarding the program and guarded the key instead: with the key out of the agent's reach and the API blocked at the firewall, this gate is the only way to a model, and it writes everything down.

## Use it if

- an agent with a shell runs on a machine that also holds your API key
- you want sessions the agent can't stretch: a model only while one is open, and only up to a budget
- you need a record of every model call that the agent itself can't edit

An agent can get around the gate unless you set up two things on its machine. It takes a few minutes more than a one-line install:

- run the agent as its own user, one that can't read the key or edit the gate's files
- block that user from reaching the provider's API at your firewall

## Install

Python 3, standard library only, one file:

```sh
curl -O https://raw.githubusercontent.com/justin-rhee/model-gate/main/src/model_gate.py
```

Write a config, then run the gate as a user the agent can't become:

```sh
TOKEN_FILE=/etc/model-gate/key       # readable by the gate's user only
STATE_DIR=/run/model-gate            # holds the open marker and the token count
LOG=/var/log/model-gate/calls.jsonl
CAP=2000000                          # tokens per session; 0 means no cap
MODELS=                              # models to allow, comma separated; empty allows any
```

```sh
python3 model_gate.py serve --config gate.conf
```

Point the agent's client at `http://127.0.0.1:8791` instead of the provider. For Claude Code that's `ANTHROPIC_BASE_URL`, with any placeholder as the key, since the gate replaces it. Then `open` and `close` sessions from cron or your own script.

## How it works

1. `open` writes a marker and zeroes the session's token count, and `close` removes it. With no marker, every call gets a 403.
2. On each call the gate drops any key the agent sent, adds its own, removes provider-side tools like web search that would reach outside your machine inside the model call, and forwards the rest.
3. It reads the token counts from the response, streamed or not, and adds them to the session total. Once the total reaches the cap, calls get a 429.
4. Every call, forwarded or refused, becomes one JSON line in the log. Headers are never written, so the key can't end up there, and a key the provider rejects writes an alarm file instead of failing quietly.

Full request and response bodies are kept only if you set `BODIES_DIR`.

## Why not an environment variable or a spending limit?

An agent with a shell can read its own environment, so a key there is a key it holds. A provider's spending limit covers the whole account for the month, knows nothing of your sessions, and records nothing of what was asked.

## What it won't do

- protect the key from anyone who can become the gate's user or root
- stop a session exactly at the cap: it checks before each call, so the last call can go over by one call's tokens
- count tokens past the first 4 MB of a response (the largest real response I saw was about 50 KB)
- speak other providers' formats: it's written for Anthropic's Messages API, and another provider's token fields won't count toward the cap
- schedule sessions for you

## How I tested it

- 16 tests against a fake API on localhost, in about ten seconds: `python3 tests/test_model_gate.py`
- removing any one of four protections fails the suite: the closed-session check, dropping the agent's own key, the cap, and reading streamed token counts
- it ran in front of every session of Fallow's main run

<details>
<summary>More on testing</summary>

Before Fallow's first session, the token count read zero on every real call, so the cap could never fire. Two causes: the response came back compressed, and the count was pulled out with a text pattern that missed real, nested JSON. The gate now asks for uncompressed responses, decompresses anyway when one arrives, and decodes the JSON properly. Tests cover streamed, compressed and nested counts. A response also ends only after its line is written, so a client can't slip a call in before the last one is counted.

</details>

## Contributing

The most useful contribution is support for another provider's token fields, so the cap can count them. A pull request with a test that sends a real-shaped response is the best way in.

## License

MIT. See [LICENSE](LICENSE). No warranty. Security notes and how to report a problem: [SECURITY.md](SECURITY.md).

<!-- related:start -->
## Related

- [bash-havoc-guard](https://github.com/justin-rhee/bash-havoc-guard): blocks credential dumps, outbound network calls and destructive commands
- [path-fence](https://github.com/justin-rhee/path-fence): refuses credential-shaped file reads before they happen

Part of a small set of tools I pulled out of my own agent harness. I use them myself and read every issue. More on my [GitHub profile](https://github.com/justin-rhee).
<!-- related:end -->
