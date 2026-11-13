//! # policy-core
//!
//! The single source of truth for AgentVault's spending rules.
//!
//! The AI agent is treated as **untrusted input**. Every action it proposes is
//! run through [`evaluate`], which either approves it or returns the exact
//! [`Reason`] it was rejected. The NEAR vault contract calls this very same
//! function on-chain, and the red-team harness calls it natively, so what we
//! test is what gets deployed.
//!
//! This crate has zero dependencies on purpose: it is small enough to audit in
//! one sitting and builds anywhere.

/// Nanoseconds per second (NEAR block timestamps are in nanoseconds).
pub const NS_PER_SEC: u64 = 1_000_000_000;
/// yoctoNEAR per 1 NEAR (10^24).
pub const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;

/// A recipient the agent is allowed to pay, with its own per-payment ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowEntry {
    pub recipient: String,
    pub cap_per_tx: u128,
}

/// Owner-defined limits. The agent can never change these.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Global ceiling for a single payment (yoctoNEAR).
    pub per_tx_cap: u128,
    /// Maximum total spend inside any rolling `window_ns` (yoctoNEAR).
    pub budget: u128,
    /// Length of the rolling budget window in nanoseconds (e.g. 24h).
    pub window_ns: u64,
    /// Minimum gap between two approved actions, nanoseconds.
    pub cooldown_ns: u64,
    /// Absolute time (ns) after which the agent session is dead.
    pub expires_at_ns: u64,
    /// Maximum number of approved actions for this session.
    pub max_actions: u32,
    /// Kill switch. When true, every action is rejected.
    pub paused: bool,
    /// The only addresses the agent may pay.
    pub allowlist: Vec<AllowEntry>,
}

impl Policy {
    pub fn entry(&self, to: &str) -> Option<&AllowEntry> {
        self.allowlist.iter().find(|e| e.recipient == to)
    }
}

/// Mutable bookkeeping that the vault persists between actions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    /// (timestamp_ns, amount) of approved spends still inside the window.
    pub spends: Vec<(u64, u128)>,
    pub last_action_ns: Option<u64>,
    pub actions_used: u32,
}

impl State {
    /// Total approved spend inside the rolling window ending at `now`.
    pub fn spent_in_window(&self, now: u64, window_ns: u64) -> u128 {
        self.spends
            .iter()
            .filter(|(ts, _)| ts.saturating_add(window_ns) > now)
            .fold(0u128, |acc, (_, a)| acc.saturating_add(*a))
    }
}

/// Why an action was refused. Codes are stable strings used in on-chain events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Paused,
    SessionExpired,
    UsageLimitReached,
    ZeroAmount,
    RecipientNotAllowed,
    RecipientCapExceeded,
    PerTxCapExceeded,
    CooldownActive,
    BudgetExceeded,
    InsufficientBalance,
}

impl Reason {
    pub fn code(&self) -> &'static str {
        match self {
            Reason::Paused => "PAUSED",
            Reason::SessionExpired => "SESSION_EXPIRED",
            Reason::UsageLimitReached => "USAGE_LIMIT_REACHED",
            Reason::ZeroAmount => "ZERO_AMOUNT",
            Reason::RecipientNotAllowed => "RECIPIENT_NOT_ALLOWED",
            Reason::RecipientCapExceeded => "RECIPIENT_CAP_EXCEEDED",
            Reason::PerTxCapExceeded => "PER_TX_CAP_EXCEEDED",
            Reason::CooldownActive => "COOLDOWN_ACTIVE",
            Reason::BudgetExceeded => "BUDGET_EXCEEDED",
            Reason::InsufficientBalance => "INSUFFICIENT_BALANCE",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Reason::Paused => "Vault is paused by the owner (kill switch)",
            Reason::SessionExpired => "Agent session has expired",
            Reason::UsageLimitReached => "Agent used all of its allowed actions",
            Reason::ZeroAmount => "Amount must be greater than zero",
            Reason::RecipientNotAllowed => "Recipient is not on the owner's allowlist",
            Reason::RecipientCapExceeded => "Amount exceeds this recipient's per-payment cap",
            Reason::PerTxCapExceeded => "Amount exceeds the global per-payment cap",
            Reason::CooldownActive => "Too soon after the previous action (cooldown)",
            Reason::BudgetExceeded => "Payment would exceed the rolling budget",
            Reason::InsufficientBalance => "Vault balance (after reserve) is too low",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Rejected(Reason),
}

impl Verdict {
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::Allowed => "ALLOWED",
            Verdict::Rejected(r) => r.code(),
        }
    }
}

/// Pure check. Returns the first rule the action breaks, or `None` if it is fine.
/// `available` is the vault balance the agent may spend (after storage/gas reserve).
pub fn check(
    policy: &Policy,
    state: &State,
    now: u64,
    available: u128,
    to: &str,
    amount: u128,
) -> Option<Reason> {
    if policy.paused {
        return Some(Reason::Paused);
    }
    if now >= policy.expires_at_ns {
        return Some(Reason::SessionExpired);
    }
    if state.actions_used >= policy.max_actions {
        return Some(Reason::UsageLimitReached);
    }
    if amount == 0 {
        return Some(Reason::ZeroAmount);
    }
    let entry = match policy.entry(to) {
        Some(e) => e,
        None => return Some(Reason::RecipientNotAllowed),
    };
    if amount > entry.cap_per_tx || amount > policy.per_tx_cap {
        return Some(if entry.cap_per_tx <= policy.per_tx_cap {
            Reason::RecipientCapExceeded
        } else {
            Reason::PerTxCapExceeded
        });
    }
    if let Some(last) = state.last_action_ns {
        if policy.cooldown_ns > 0 && now < last.saturating_add(policy.cooldown_ns) {
            return Some(Reason::CooldownActive);
        }
    }
    let spent = state.spent_in_window(now, policy.window_ns);
    if spent.saturating_add(amount) > policy.budget {
        return Some(Reason::BudgetExceeded);
    }
    if amount > available {
        return Some(Reason::InsufficientBalance);
    }
    None
}

/// Evaluate an action. On `Allowed` the spend is committed to `state`;
/// on `Rejected` the state is left untouched.
pub fn evaluate(
    policy: &Policy,
    state: &mut State,
    now: u64,
    available: u128,
    to: &str,
    amount: u128,
) -> Verdict {
    if let Some(reason) = check(policy, state, now, available, to, amount) {
        return Verdict::Rejected(reason);
    }
    state
        .spends
        .retain(|(ts, _)| ts.saturating_add(policy.window_ns) > now);
    state.spends.push((now, amount));
    state.last_action_ns = Some(now);
    state.actions_used = state.actions_used.saturating_add(1);
    Verdict::Allowed
}

/// Same as [`evaluate`] but never changes anything (used by view calls).
pub fn dry_run(
    policy: &Policy,
    state: &State,
    now: u64,
    available: u128,
    to: &str,
    amount: u128,
) -> Verdict {
    let mut scratch = state.clone();
    evaluate(policy, &mut scratch, now, available, to, amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: u128 = YOCTO_PER_NEAR;
    const T0: u64 = 1_700_000_000 * NS_PER_SEC;
    const DAY: u64 = 86_400 * NS_PER_SEC;

    fn policy() -> Policy {
        Policy {
            per_tx_cap: N,
            budget: 3 * N,
            window_ns: DAY,
            cooldown_ns: 10 * NS_PER_SEC,
            expires_at_ns: T0 + 3600 * NS_PER_SEC,
            max_actions: 20,
            paused: false,
            allowlist: vec![
                AllowEntry {
                    recipient: "alice.testnet".into(),
                    cap_per_tx: 2 * N,
                },
                AllowEntry {
                    recipient: "bob.testnet".into(),
                    cap_per_tx: N / 2,
                },
            ],
        }
    }

    fn run(p: &Policy, s: &mut State, secs: u64, to: &str, amt: u128) -> Verdict {
        evaluate(p, s, T0 + secs * NS_PER_SEC, 100 * N, to, amt)
    }

    #[test]
    fn allows_valid_payment() {
        let (p, mut s) = (policy(), State::default());
        assert_eq!(run(&p, &mut s, 0, "alice.testnet", N / 2), Verdict::Allowed);
        assert_eq!(s.actions_used, 1);
    }

    #[test]
    fn rejects_unknown_and_lookalike_recipients() {
        let (p, mut s) = (policy(), State::default());
        for to in [
            "attacker.testnet",
            "a1ice.testnet",
            "alice.testnet.evil",
            "Alice.testnet",
            "",
        ] {
            assert_eq!(
                run(&p, &mut s, 0, to, N / 10),
                Verdict::Rejected(Reason::RecipientNotAllowed),
                "{to}"
            );
        }
        assert_eq!(s, State::default(), "rejections must not change state");
    }

    #[test]
    fn caps() {
        let (p, mut s) = (policy(), State::default());
        assert_eq!(
            run(&p, &mut s, 0, "bob.testnet", N),
            Verdict::Rejected(Reason::RecipientCapExceeded)
        );
        assert_eq!(
            run(&p, &mut s, 0, "alice.testnet", 2 * N),
            Verdict::Rejected(Reason::PerTxCapExceeded)
        );
        assert_eq!(
            run(&p, &mut s, 0, "alice.testnet", u128::MAX),
            Verdict::Rejected(Reason::PerTxCapExceeded)
        );
    }

    #[test]
    fn zero_amount() {
        let (p, mut s) = (policy(), State::default());
        assert_eq!(
            run(&p, &mut s, 0, "alice.testnet", 0),
            Verdict::Rejected(Reason::ZeroAmount)
        );
    }

    #[test]
    fn split_payments_hit_rolling_budget() {
        let (p, mut s) = (policy(), State::default());
        let amt = N * 9 / 10;
        for i in 0..3 {
            assert_eq!(
                run(&p, &mut s, i * 11, "alice.testnet", amt),
                Verdict::Allowed
            );
        }
        assert_eq!(
            run(&p, &mut s, 33, "alice.testnet", amt),
            Verdict::Rejected(Reason::BudgetExceeded)
        );
    }

    #[test]
    fn budget_recovers_after_window() {
        let mut p = policy();
        p.expires_at_ns = T0 + 3 * DAY;
        let mut s = State::default();
        for i in 0..3 {
            assert_eq!(
                run(&p, &mut s, i * 11, "alice.testnet", N * 9 / 10),
                Verdict::Allowed
            );
        }
        assert_eq!(
            run(&p, &mut s, 100, "alice.testnet", N / 2),
            Verdict::Rejected(Reason::BudgetExceeded)
        );
        assert_eq!(
            run(&p, &mut s, 86_400 + 100, "alice.testnet", N / 2),
            Verdict::Allowed
        );
    }

    #[test]
    fn cooldown() {
        let (p, mut s) = (policy(), State::default());
        assert_eq!(
            run(&p, &mut s, 0, "alice.testnet", N / 10),
            Verdict::Allowed
        );
        assert_eq!(
            run(&p, &mut s, 1, "alice.testnet", N / 10),
            Verdict::Rejected(Reason::CooldownActive)
        );
        assert_eq!(
            run(&p, &mut s, 10, "alice.testnet", N / 10),
            Verdict::Allowed
        );
    }

    #[test]
    fn expiry_usage_pause_balance() {
        let mut p = policy();
        let mut s = State::default();
        assert_eq!(
            run(&p, &mut s, 3601, "alice.testnet", N / 10),
            Verdict::Rejected(Reason::SessionExpired)
        );

        p.max_actions = 1;
        assert_eq!(
            run(&p, &mut s, 0, "alice.testnet", N / 10),
            Verdict::Allowed
        );
        assert_eq!(
            run(&p, &mut s, 60, "alice.testnet", N / 10),
            Verdict::Rejected(Reason::UsageLimitReached)
        );

        let mut p2 = policy();
        p2.paused = true;
        assert_eq!(
            run(&p2, &mut State::default(), 0, "alice.testnet", N / 10),
            Verdict::Rejected(Reason::Paused)
        );

        let p3 = policy();
        let v = evaluate(
            &p3,
            &mut State::default(),
            T0,
            N / 10,
            "alice.testnet",
            N / 2,
        );
        assert_eq!(v, Verdict::Rejected(Reason::InsufficientBalance));
    }

    #[test]
    fn dry_run_never_mutates() {
        let (p, s) = (policy(), State::default());
        let v = dry_run(&p, &s, T0, 100 * N, "alice.testnet", N / 2);
        assert_eq!(v, Verdict::Allowed);
        assert_eq!(s, State::default());
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    /// 200k random hostile actions. An independent oracle re-checks every
    /// approved action against the invariants a user actually cares about.
    #[test]
    fn fuzz_invariants_hold() {
        for seed in 1..=4u64 {
            let mut rng = Lcg(seed);
            let mut p = policy();
            p.expires_at_ns = u64::MAX;
            p.max_actions = if seed % 2 == 0 { 50 } else { u32::MAX };
            let mut s = State::default();
            let mut approved: Vec<(u64, u128)> = vec![];
            let mut now = T0;
            let recips = [
                "alice.testnet",
                "bob.testnet",
                "attacker.testnet",
                "a1ice.testnet",
                "x",
            ];
            let amounts = [
                0,
                1,
                N / 10,
                N / 2,
                N,
                2 * N,
                3 * N,
                u128::MAX,
                u128::MAX - 1,
            ];
            for _ in 0..50_000 {
                now = now.saturating_add((rng.next() % (6 * 3600)) * NS_PER_SEC / 3);
                let to = recips[(rng.next() % recips.len() as u64) as usize];
                let amt = amounts[(rng.next() % amounts.len() as u64) as usize];
                if let Verdict::Allowed = evaluate(&p, &mut s, now, 1000 * N, to, amt) {
                    let e = p
                        .entry(to)
                        .expect("approved payment to a non-allowlisted recipient");
                    assert!(
                        amt > 0 && amt <= e.cap_per_tx && amt <= p.per_tx_cap,
                        "cap broken"
                    );
                    approved.push((now, amt));
                    let in_window: u128 = approved
                        .iter()
                        .filter(|(t, _)| t + p.window_ns > now)
                        .map(|(_, a)| *a)
                        .sum();
                    assert!(in_window <= p.budget, "rolling budget broken");
                    assert!(
                        approved.len() as u64 <= p.max_actions as u64,
                        "usage cap broken"
                    );
                }
            }
            assert!(!approved.is_empty());
        }
    }
}
