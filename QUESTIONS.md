# Review notes: bringing the router handshake under Noise

Branch: `feat/router-noise-handshake`, two commits on `b184df670`.

This is the write-up that would otherwise be a PR description, plus the calls I made
that I would rather you confirmed than discovered. Sections marked **Decision** need
an answer before this could go to `staging`; the rest are things worth knowing.

## What the branch does

The router's handshake skipped its restrictions check whenever either side claimed to
be a prover, and the claim was unauthenticated - `node_type` rode in a plaintext
`ChallengeRequest`, `restrictions_id` in a `ChallengeResponse`, and the signature
covered only a pair of nonces. The branch moves the router onto the Noise-XX handshake
that PR #4354 built for the gateway, under its own binding domain, so that both fields
are bound to the session transcript and the restrictions check applies to every peer.

The legacy handshake still works on both sides; nothing about the wire protocol becomes
mandatory until a consensus version is scheduled for it.

## 1. The prover exemption is gone, because its cause is gone — **Decision**

The exemption traces to `29ed22536` (Jun 2024) and `1b5e7402c`. Its cause is mechanical:
`ProverLedgerService::latest_restrictions_id` returns `Field::zero()`, and
`node/src/prover/router.rs` hard-coded the same, because a prover has no ledger.

But `Restrictions` needs no ledger. `Restrictions::load` parses a compile-time list
embedded in the network definition, and `VM::restrictions` is literally
`Restrictions::load()?` (snarkVM `synthesizer/src/vm/mod.rs:240`). `BootstrapClient::new`
already loads it this way from a node with no ledger at all.

So the first commit has provers load and disclose the real value, and the Noise path
checks the restrictions ID unconditionally. **Please confirm** you agree the exemption
was an artifact rather than a deliberate policy — this is the one place where I am
overturning an explicit decision by someone else, on the strength of the code rather
than a written rationale, and neither commit that introduced it says why.

Backwards compatibility: nobody checks a prover's restrictions ID today, so a patched
prover simply starts passing a check that was being skipped. No node rejects anything
it previously accepted.

## 2. The legacy path keeps the bypass — **Decision**

The task description said the bypass at `handshake.rs:415` goes away. On the Noise path
it has. On the legacy path I left it, for two reasons:

- Removing it now rejects every prover still running a build that discloses a zero
  restrictions ID. That is a connectivity break during exactly the window where the
  fleet is mixed.
- It buys little against an adversary. `restrictions_id` is public, so an attacker who
  wanted to pass the check could simply echo the right value. What the check actually
  excludes is *honestly* forked or misconfigured peers, and what the report's attack
  needed was the unauthenticated `node_type` - which is only unauthenticated on the
  legacy path, and only for as long as that path exists.

The consequence is that the reported defect is not fully closed until
`LEGACY_HANDSHAKE_EXPIRY` is set, which is item 3. If you would rather close it sooner
at the cost of shutting out unpatched provers, that is a one-line change and I will make
it.

## 3. `LEGACY_HANDSHAKE_EXPIRY` is unscheduled, and there is a real blocker — **Decision**

`NOISE_HANDSHAKE_ACTIVATION` is `Some(ConsensusVersion::V21)`; `LEGACY_HANDSHAKE_EXPIRY`
is `None` with a TODO. Two things stand in the way of scheduling the expiry:

- **The pinned snarkVM stops at V21**, which is already the gateway's own legacy expiry.
  The router needs a later version. This is the same position PR #4354 shipped in before
  `d994d4725` set its constants.
- **A prover reports block height 0** (`ProverLedgerService::latest_block_height`), so it
  can never evaluate a consensus gate. It can neither reach an expiry nor be shut out by
  its own copy of one. Today I have provers bypass the gate on the *initiating* side and
  always offer Noise, mirroring how `Router::is_valid_message_version` (`lib.rs:209`)
  forces height-blind node types to the latest message version. But their *responding*
  side will keep accepting legacy forever, so provers would be the last legacy-accepting
  nodes on the network.

That needs solving before the expiry lands. Options I can see, none of them obviously
right: give the prover a height source (it does learn peer heights via `PeerResponse`,
though that is attacker-influenced); have the prover's ledger service report the height
of its best peer; or accept that provers are responders of last resort and exempt them
explicitly. I did not want to pick one of these unprompted - it is a change to what a
prover tracks, not to the handshake.

**Is V21 the right activation version?** It is `u32::MAX` on mainnet, testnet and canary
today, so nothing fires until a height is assigned. But it is also the version at which
the gateway stops accepting legacy, so the router would *begin* its migration at the
version the gateway *ends* its own. If you would rather they were staged, say which
version you want.

## 4. Provers and bootstrap clients always initiate Noise — **Decision**

Because they cannot evaluate the gate (item 3). The cost is a window: a patched prover
dialing an *unpatched* client fails, because the old node's handshake codec reads the
`NOISE_MAGIC` prefix as a 4.3 GiB frame length and hangs up. Provers dial clients and
validators, so during the rollout this is a real connectivity gap for provers.

The alternatives were: ship the gate unscheduled and leave provers on legacy (no gap, but
nothing activates until a follow-up); or have provers dial Noise and retry legacy on a
hang-up (no gap, but adds a reconnect path nothing else in the codebase has). I took the
one you picked in conversation; flagging the cost here because it is the part that will
be felt operationally.

## 5. Two existing tests changed, for behaviour that genuinely changed — **Review**

Neither was a test bug. Both are consequences of the four-message pattern, and both are
shared with the gateway:

- **The responder now finishes first.** It registers the peer the moment it sends its
  verdict, while the initiator is still verifying the proof that came back. The legacy
  handshake had the initiator finish last. Two `connect.rs` tests waited on the responder
  alone and then asserted about the initiator; they now wait on both. Worth deciding
  whether you are happy that a responder briefly holds a connection the initiator may
  still reject - the gateway already accepts this.
- **A rejected peer is no longer told why.** `ensure_peer_is_allowed` fires before the
  Noise pattern begins, which is the point of checking there - a peer we would never
  accept costs us no key derivation - but leaves no channel to answer over. The
  `"no external peers allowed"` string assertion in `test_validator_connection` is gone;
  the assertion that the connection is refused stays. I could not find a way to keep both
  properties: sending a reason requires reaching message 4, which requires the very key
  derivation the early check exists to avoid.

## 6. `ProverLedgerService::latest_restrictions_id` still returns zero — **Review**

I corrected its comment but not its value. Nothing calls it: it exists for the gateway's
handshake, and a prover runs no gateway. Its siblings `latest_block` and `latest_leader`
are `unreachable!()`, which would be the honest thing here too - but `unreachable!()` in
a production path crashes the node if I am wrong about the call graph, and the change is
not needed for this work. Leaving a wrong-but-dead value with an accurate comment is the
other kind of wrong. Your call which you prefer.

## 7. `genesis_header` costs 280 bytes per handshake, and is nearly self-enforcing — **Review**

I kept it in the router's `PeerInfo` for parity with the legacy `ChallengeResponse`. Two
observations that might change your mind:

- It is the reason the router's third message is 524 bytes of payload where the gateway's
  is 307. Against the 1024-byte `MAX_HANDSHAKE_MSG_LEN` there is comfortable headroom, and
  `the_largest_handshake_message_fits_a_noise_message` pins it, but the router is now the
  binding constraint on that limit rather than the gateway.
- The explicit comparison in `verify_peer_info` is close to redundant. `Header::from_bytes_le`
  enforces the network's genesis values at height zero, so a peer cannot even construct a
  header claiming to be a genesis it is not - the payload fails to parse first. The test for
  this had to tamper with the wire bytes after serialization, because the type system would
  not let it build the input.

Dropping it, or sending a hash instead, would be a wire change I did not want to make
unprompted. Flagging it as available if the size ever matters.

## 8. The legacy path still drops pipelined bytes — **FYI, pre-existing**

The router's legacy handshake reads through a buffering codec, so it can pull bytes off
the socket that belong to the messages which follow, and those are lost when the `Framed`
is dropped. The gateway logs this (`note_legacy_handshake_end`); the router does neither.
Pre-existing, untouched, and it goes away with the legacy path - noted only because I was
working in that function and did not fix it.

## What I verified rather than assumed

- V21 is `u32::MAX` in `MAINNET_V0`, `TESTNET_V0` and `CANARY_V0` consensus height tables,
  so the activation cannot fire until a height is assigned.
- The `test` feature of `snarkos-node-router` does *not* reach the release binary:
  `cargo tree -p snarkos -e features --no-dev-dependencies` shows only `default`. If it
  ever did, `pinned_handshake_protocol` would force Noise regardless of the gate. The
  gateway has the same exposure.
- Message 3 is 524 bytes of payload against a 1024-byte limit.
- The router and gateway binding domains differ, pinned by a unit test that compares them
  directly rather than by inspection.

## Tests run

`cargo clippy --workspace --all-targets -- -D warnings` and `cargo +nightly fmt --all --check`
are clean; the pre-commit hook ran on both commits.

| Crate | Result |
| --- | --- |
| `snarkos-node-network` | 17 passed |
| `snarkos-node-router-messages` | 19 passed |
| `snarkos-node-router` | 30 passed (lib, connect, disconnect, cleanups, heartbeat, noise) |
| `snarkos-node` | 39 passed (lib, handshake, disconnect, peering, bootstrap_handshake) |
| `snarkos-node-bft` | `gateway_noise` only, 9 passed |
| `snarkos-node-bft-ledger-service` | 7 passed |

The two BFT crates are touched by comment-only changes. I ran `gateway_noise` against the
final tree because it is the suite that would notice if the shared Noise module or the
bootstrap client's dispatch had regressed; I did not run the whole `snarkos-node-bft`
suite, which is long and untouched by anything behavioural here.

One caveat on the first row: `snarkos-node-network` has no CI coverage on this branch's
base. `.circleci/config.yml` defines a `node-network` job and lists it in no workflow, so
those 17 tests have never run there - and this branch edits that crate, making
`MAX_HANDSHAKE_MSG_LEN` public. So the number above is from my machine, and nothing else
will check it until the job is wired into a workflow. That is being fixed separately,
along with two other gaps in the same matrix; it is deliberately not bundled here, since
it should land whether or not this branch does.

## New files

- `node/router/messages/src/helpers/handshake.rs` - the router's Noise payloads, mirroring
  `node/bft/events/src/helpers/handshake.rs`. Reuses `encode_payload`/`decode_payload` from
  `snarkos-node-bft-events` rather than duplicating them; router-messages already depended
  on that crate.
- `node/router/tests/noise.rs` - end-to-end tests.

No new crates, dependencies, traits or error types. One visibility change:
`MAX_HANDSHAKE_MSG_LEN` in `node/network/src/noise.rs` is now `pub`, so a caller adding a
field to a payload can pin that it still fits.
