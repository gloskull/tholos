# V2 anti-snipe throttle analysis

This note analyses whether the anti-snipe extension mechanism in `register()`
needs a per-position throttle — a flag (or restriction to first-time deposits
only) that would prevent a single address, or a coordinated set of addresses,
from retriggering the extension more than once. It follows the same approach as
[V1_MAINNET_PARAMETERS.md](V1_MAINNET_PARAMETERS.md) and
[V2_BOND_SIZING.md](V2_BOND_SIZING.md): work from the contract as it actually
exists, model the cost a potential attacker faces, and only recommend adding
mechanism where the existing constraints leave a real gap.

## Background: how the extension works today

`register()` in `contracts/tholos-v2/src/lib.rs` applies an anti-snipe
extension whenever a qualifying deposit lands within the last
`anti_snipe_extension_secs` of the current soft deadline:

```rust
if now >= resolution.registration_deadline
    .saturating_sub(assertion.policy.anti_snipe_extension_secs)
{
    let extended = now + assertion.policy.anti_snipe_extension_secs;
    resolution.registration_deadline =
        extended.min(resolution.registration_hard_deadline);
}
```

Two hard limits bound this:

1. **`registration_hard_deadline`**: set once at `dispute()` time as
   `now + anti_snipe_hard_max_secs`. No sequence of extensions can push
   `registration_deadline` past this value. `initialize()` enforces
   `anti_snipe_hard_max_secs >= registration_duration_secs`, so the hard cap
   is always at least as far out as the original window.

2. **`#155` effective minimum** (`effective_minimum =
   min_resolution_bond.min(max_position.saturating_sub(previous_amount))`):
   every deposit — whether first-time or a top-up — must individually meet
   this floor. A deposit that is too small to meet the floor is rejected
   outright, so it cannot trigger the extension at all.

There is no per-position "already extended" flag and no restriction to
first-time deposits only. A single address can retrigger the extension on
each subsequent top-up, and a Sybil actor funding fresh addresses was never
affected by #155 (a first-time deposit was always required to clear
`min_resolution_bond`).

---

## Part 1: the attack surface and its actual cost

### Single-address repeated top-up

An address that has already registered can retrigger the extension by
top-up. The maximum number of extensions it can trigger is bounded by
`max_position / min_resolution_bond`: each qualifying top-up must be at
least `min_resolution_bond` (unless it's filling the final headroom gap),
and the total position cannot exceed `max_position`. With typical parameters:

```text
max_position = 5 × min_resolution_bond  →  at most 5 extensions per address
max_position = 10 × min_resolution_bond →  at most 10 extensions per address
```

Each of those extensions costs exactly `min_resolution_bond` in real
token capital — capital that is now locked in the position and subject to
forfeiture if the address is on the losing side.

The number of extensions the entire registration window can absorb is
bounded by `max_total_weight`:

```text
Maximum extensions from all addresses combined
    ≤ floor((max_total_weight - 2 × base_bond) / min_resolution_bond)
```

(The two `base_bond` fixed positions — asserter and disputer — are already
locked at `dispute()` time and cannot trigger further extensions.)

### Sybil actor with fresh addresses

A Sybil attacker funding `n` fresh addresses can trigger up to `n` first-time
extensions, each costing `min_resolution_bond` and again capped by
`max_total_weight`. A Sybil attack is therefore not qualitatively different
from the single-address repeated top-up: both are bounded by
`max_total_weight` and both cost at least `min_resolution_bond` per extension
trigger.

### The hard deadline: an unconditional ceiling on total exposure

The critical constraint that does not appear in either of the above counts
is `registration_hard_deadline`. Regardless of how many extensions fire, the
soft deadline can never be pushed past `dispute_time + anti_snipe_hard_max_secs`.
The total number of extensions the hard cap absorbs is:

```text
Maximum extensions before hard cap =
    floor((anti_snipe_hard_max_secs - registration_duration_secs)
          / anti_snipe_extension_secs)
```

For the profiles in [V2_BOND_SIZING.md](V2_BOND_SIZING.md):

| Profile | `T_reg` | `T_ext` | `T_hard` | Max extensions |
| ------- | ------- | ------- | -------- | -------------- |
| Private beta | 3 600 s (1 h) | 300 s (5 min) | 7 200 s (2 h) | 12 |
| Public testnet | 14 400 s (4 h) | 600 s (10 min) | 43 200 s (12 h) | 48 |
| Higher-value mainnet | 43 200 s (12 h) | 1 800 s (30 min) | 172 800 s (48 h) | 72 |

The hard cap does two things at once: it limits the wall-clock damage an
attacker can do (registration can only be extended so far), and it limits
the *number* of extension triggers that are even possible, because the
soft deadline stops moving once it reaches the hard cap. This means
`max_total_weight` and `registration_hard_deadline` together determine the
worst-case attack budget: the attacker needs at most
`floor((T_hard - T_reg) / T_ext)` extensions worth of capital, each costing
at least `min_resolution_bond`.

---

## Part 2: is the current deterrent sufficient?

The question the issue raises is whether the existing constraints —
`registration_hard_deadline` as the absolute ceiling and #155's
`effective_minimum` as the per-deposit floor — already make repeated
triggering sufficiently costly without any additional per-position throttle.

### The attacker's cost floor

An attacker who wants to push `registration_deadline` to `registration_hard_deadline`
must trigger enough extensions to span the gap `T_hard - T_reg`. The number
of extensions required is `ceil((T_hard - T_reg) / T_ext)`, and each
extension costs at least `min_resolution_bond`. Total attack cost:

```text
attack_cost_min = ceil((T_hard - T_reg) / T_ext) × min_resolution_bond
```

For the mainnet candidate profile above (`T_hard - T_reg = 36 h`, `T_ext = 30 min`,
`min_resolution_bond = base_bond`):

```text
attack_cost_min = 72 × base_bond
```

A deployment with `base_bond = 100` tokens would require at least 7 200 tokens
of real capital held at risk through the entire dispute, every unit of it
subject to forfeiture on the losing side. This is not a cheap or consequence-free
operation.

### Comparing to `max_total_weight`

The attack cost floor above — `72 × base_bond` — far exceeds the
`max_total_weight = 30 × base_bond` cap for the mainnet profile (and the
`28 × base_bond` of third-party headroom once the asserter and disputer
bonds are reserved). This is precisely why the attacker *cannot actually
trigger all 72 extensions* under that profile: `max_total_weight` is
exhausted long before the hard deadline is reached, making it the binding
constraint. The real maximum attacker spend is bounded by the lower of the
two limits:

```text
practical_attack_ceiling
    = min(attack_cost_min, max_total_weight - 2 × base_bond)
    = min(72 × base_bond, 28 × base_bond)
    = 28 × base_bond
```

For the mainnet candidate profile, the Sybil / top-up attacker cannot push
the deadline all the way to `registration_hard_deadline` — the
`max_total_weight` cap kicks in first and the extension simply stops firing
once the total is full.

**This means the existing configuration already limits both the attacker's
total capital cost and the total deadline extension to what `max_total_weight`
can absorb, which is less than what `T_hard` would theoretically permit.**

### The legitimate-participant mirror

Every constraint that binds an attacker also binds a genuine late-arriving
participant. A participant who wants to register multiple top-ups late in the
window faces the same `min_resolution_bond` floor and the same `max_position`
cap. A throttle that restricts the extension to the first deposit only, or
marks a per-position "has extended" flag, would protect extension triggers
from repeated use — but would also prevent a legitimate participant who
top-ups late from triggering the extension their follow-on capital deserves.

The contract currently cannot and intentionally does not distinguish "attacker
paying to extend" from "legitimate participant arriving late": both look
identical on-chain (real bonded capital, correctly sized, landing late). Any
mechanism that suppresses the extension for the second case suppresses it
for both.

---

## Part 3: two throttle candidates and their trade-offs

For completeness, the two mechanisms raised in the issue are analysed here.

### Option A: first-deposit-only extension

The extension triggers only when `existing == None` (the voter has no prior
position). Top-ups by an already-registered address never re-extend the
deadline.

**What it prevents**: a single address triggering more than one extension.

**What it costs**: a legitimate voter who registered early and tops up in
the final extension window does not extend the deadline for their new capital.
If their top-up is the late arrival that the anti-snipe mechanism is supposed
to protect, the protection simply does not fire.

**Net effect**: Sybil actors funding fresh addresses are unaffected entirely.
Single-address repeated top-ups are throttled to one extension per address.
The Sybil path is the dominant attack vector anyway, so Option A provides
minimal security improvement while meaningfully reducing coverage for
legitimate top-ups.

### Option B: per-assertion extended flag

The assertion state carries a flag `has_been_extended: bool`. Once set,
no further qualifying deposit triggers an extension.

**What it prevents**: every extension after the first, from any address.

**What it costs**: the anti-snipe mechanism functionally degrades to a
one-shot soft deadline extension. An attacker who wants to snipe only needs
to wait until after the first legitimate extension fires (which they cannot
control), then times their deposit for just before the new soft deadline
(before the flag makes no difference). More importantly, genuine
late-arriving participants who show up after the first extension get no
further protection at all.

**Net effect**: this is the strongest throttle and the most damaging to the
mechanism's core purpose. The anti-snipe protection is designed precisely
for repeated late arrivals; a per-assertion flag disables it after one use.

### Why both options make the same core trade-off worse

The anti-snipe mechanism's value is not primarily in deterring attackers —
it is in ensuring that the registration deadline stays open long enough for
every *genuine* late capital to be counted. The hard deadline already bounds
the worst-case delay an attacker can impose. Both throttle options reduce
the mechanism's coverage for the legitimate case without meaningfully
changing the attacker's actual capital cost, because the Sybil path is
unaffected by any per-position restriction.

---

## Part 4: verdict

The existing combination of constraints is sufficient:

1. **`registration_hard_deadline`** provides an unconditional wall-clock
   ceiling on how far registration can be extended, regardless of how many
   times the soft deadline is pushed.

2. **`max_total_weight`** bounds the total capital that can be deposited and
   therefore the total number of extension triggers that are even possible,
   independent of any per-position bookkeeping.

3. **#155's `effective_minimum`** ensures every deposit that triggers an
   extension costs at least `min_resolution_bond` in real, at-risk capital.

4. **The residual attack cost** (demonstrated in Part 2) is a meaningful
   multiple of `base_bond`, all of it at risk of forfeiture, making a
   pure griefing campaign unprofitable unless the attacker is also the
   losing party in the dispute.

A per-position throttle does not close a meaningful gap beyond these
existing controls. It would reduce the mechanism's utility for legitimate
late-arriving participants (Part 3) while leaving the dominant Sybil attack
path unchanged. **No throttle mechanism is recommended.**

The parameter that does most of the heavy lifting is `anti_snipe_hard_max_secs`:
it should be set based on how much additional delay an operator is willing to
tolerate beyond the baseline `registration_duration_secs`. The guidance in
[V2_BOND_SIZING.md](V2_BOND_SIZING.md) already covers that sizing; this
document confirms the mechanism requires no further changes to its trigger
logic.

---

## Appendix: parameter combinations worth double-checking

For any deployment, verify these two conditions before launch:

**1. `max_total_weight` absorbs fewer extensions than `T_hard` would allow**

```text
floor((max_total_weight - 2 × base_bond) / min_resolution_bond)
    < floor((anti_snipe_hard_max_secs - registration_duration_secs)
             / anti_snipe_extension_secs)
```

If this holds, `max_total_weight` is the binding constraint and the hard
deadline is not reachable through capital alone. If it does not hold, the
attacker can push all the way to the hard deadline and the sizing of
`anti_snipe_hard_max_secs` relative to `registration_duration_secs` matters
more.

**2. Total attack cost still exceeds `base_bond` by a meaningful margin**

```text
min(floor((max_total_weight - 2 × base_bond) / min_resolution_bond),
    ceil((anti_snipe_hard_max_secs - registration_duration_secs)
          / anti_snipe_extension_secs))
    × min_resolution_bond
    >> base_bond
```

For most deployments following the profiles in V2_BOND_SIZING.md this
will hold comfortably. Flag it if `min_resolution_bond` is set to a value
much smaller than `base_bond` or if `max_total_weight` is very close to
`2 × base_bond` (leaving almost no third-party registration headroom, which
means the anti-snipe extension can only fire one or two times regardless).
