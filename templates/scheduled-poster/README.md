# Scheduled poster

Publishes one note every 24 hours. Edit the message and interval in `bot.ns`.

## What is simulated and what is live

- `nscript run` and `nscript test-event` simulate publication: the note is
  recorded, nothing is sent and no key is used. The schedule body runs once at
  startup so you can see what it would do.
- `nscript deploy` is live. The note is signed by your NIP-46 signer and sent
  to the relays you pass:

  ```bash
  nscript deploy bot.ns --relay wss://your.relay --signer account=bunker://...
  ```

  Only the relays and signer you name are used. The script never sees a
  private key.

## Try it

```bash
./test.sh                  # check, verify the lockfile, run the schedule once
nscript inspect bot.ns     # the exact authority this bot requests
```

## Files

- `bot.ns` the bot. Each permission is commented with why it is there.
- `events/startup.expect` a line the startup run must print. This template
  has no sample event because a schedule is not triggered by one.
- `nscript.lock.json` the resolved module versions and hashes. Regenerate it
  after changing imports with `nscript package lock bot.ns --output nscript.lock.json`.
