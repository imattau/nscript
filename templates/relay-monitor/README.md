# Relay monitor

Reads NCC-10 operational-state events for services you depend on and reports
which need attention. It is read-only: it publishes nothing and holds no
signer.

## What it does and does not tell you

It reads what services *publish about themselves*. It does not probe anything,
so a service that publishes no state is unknown, not healthy. A state
published by an operator on a service's behalf is reported as `unverified`,
because confirming it needs the operator's NCC-09 grant checked, which this
template does not do.

## What is simulated and what is live

`nscript run` and `nscript test-event` feed the bot the sample events in
`events/` and nothing else. Under `nscript deploy` it subscribes to the relays
you pass and reports the states they deliver. Reading is the only live effect.

## Try it

```bash
./test.sh                  # check, verify the lockfile, run the sample events
nscript inspect bot.ns     # the exact authority this bot requests
nscript run bot.ns --event "$(cat events/degraded.json)"
```

## Files

- `bot.ns` the bot. Each permission is commented with why it is there.
- `events/` sample events. `<name>.json` is delivered to the bot and
  `<name>.expect` is a line the output must contain.
- `nscript.lock.json` the resolved module versions and hashes. Regenerate it
  after changing imports with `nscript package lock bot.ns --output nscript.lock.json`.
