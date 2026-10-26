# Moderation bot

Kicks any member whose message contains a blocked word. Edit the words in
`bot.ns`.

## What is simulated and what is live

**Everything is simulated today.** `nscript run` and `nscript test-event`
record the kick and send nothing. `nscript deploy` does not yet connect a real
Concord moderation host, so this bot cannot moderate a live community. Do not
describe a run of this template as live moderation.

## Try it

```bash
./test.sh                                   # check, verify the lockfile, run the sample events
nscript inspect bot.ns                      # the exact authority this bot requests
nscript run bot.ns --event "$(cat events/spam.json)"
```

## Files

- `bot.ns` the bot. Each permission is commented with why it is there.
- `events/` sample events. `<name>.json` is delivered to the bot and
  `<name>.expect` is a line the output must contain.
- `nscript.lock.json` the resolved module versions and hashes. Regenerate it
  after changing imports with `nscript package lock bot.ns --output nscript.lock.json`.
