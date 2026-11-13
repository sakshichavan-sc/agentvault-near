//! AgentVault on NEAR.
//!
//! Design:
//!  * The vault is a NEAR account running this contract. It holds the funds.
//!  * The owner (a separate account) controls the policy.
//!  * The AI agent holds ONLY a function-call access key on the vault account,
//!    restricted to the single method `agent_execute`. The NEAR runtime itself
//!    rejects every other action signed by that key (transfers, deploys,
//!    add-key, other methods) before this contract even runs.
//!  * `agent_execute` runs `policy_core::evaluate`. A policy violation does NOT
//!    panic: it returns a verdict and emits a NEP-297 event, so every blocked
//!    attack leaves a permanent on-chain receipt (a panic would revert the log).

use near_sdk::json_types::U128;
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};
use policy_core as pc;

/// Kept in the vault for gas/storage safety so the agent can never drain it to zero.
const RESERVE_YOCTO: u128 = 200_000_000_000_000_000_000_000; // 0.2 NEAR
const DAY_NS: u64 = 86_400 * pc::NS_PER_SEC;

#[near(serializers = [json])]
pub struct ActionResult {
    pub ok: bool,
    /// "ALLOWED" or a stable rejection code such as "BUDGET_EXCEEDED".
    pub code: String,
    pub message: String,
}

#[near(serializers = [json])]
pub struct AllowedRecipient {
    pub recipient: AccountId,
    pub cap_per_tx: U128,
}

#[near(serializers = [json])]
pub struct PolicyView {
    pub owner: AccountId,
    pub per_tx_cap: U128,
    pub budget: U128,
    pub window_secs: u64,
    pub cooldown_secs: u64,
    pub expires_at_ns: u64,
    pub max_actions: u32,
    pub paused: bool,
    pub allowlist: Vec<AllowedRecipient>,
}

#[near(serializers = [json])]
pub struct StatsView {
    pub allowed_count: u64,
    pub rejected_count: u64,
    pub actions_used: u32,
    pub spent_in_window: U128,
    pub spendable_balance: U128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    owner: AccountId,
    per_tx_cap: u128,
    budget: u128,
    window_ns: u64,
    cooldown_ns: u64,
    expires_at_ns: u64,
    max_actions: u32,
    paused: bool,
    allowlist: Vec<(AccountId, u128)>,
    spends: Vec<(u64, u128)>,
    last_action_ns: Option<u64>,
    actions_used: u32,
    allowed_count: u64,
    rejected_count: u64,
}

#[near]
impl Vault {
    /// `per_tx_cap` and `budget` are in yoctoNEAR (as strings in JSON).
    #[init]
    pub fn new(
        owner: AccountId,
        per_tx_cap: U128,
        budget: U128,
        cooldown_secs: u64,
        session_ttl_secs: u64,
        max_actions: u32,
    ) -> Self {
        Self {
            owner,
            per_tx_cap: per_tx_cap.0,
            budget: budget.0,
            window_ns: DAY_NS,
            cooldown_ns: cooldown_secs * pc::NS_PER_SEC,
            expires_at_ns: env::block_timestamp().saturating_add(session_ttl_secs * pc::NS_PER_SEC),
            max_actions,
            paused: false,
            allowlist: vec![],
            spends: vec![],
            last_action_ns: None,
            actions_used: 0,
            allowed_count: 0,
            rejected_count: 0,
        }
    }

    // ───────────────────────── agent entry point ─────────────────────────

    /// The ONLY method the agent's access key may call.
    /// Not `#[payable]`, so the runtime refuses any attached deposit.
    pub fn agent_execute(&mut self, to: AccountId, amount: U128) -> ActionResult {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "agent_execute can only be called with the vault's own access key"
        );
        let now = env::block_timestamp();
        let policy = self.policy();
        let mut state = self.state();
        let verdict = pc::evaluate(&policy, &mut state, now, self.available(), to.as_str(), amount.0);

        match verdict {
            pc::Verdict::Allowed => {
                self.spends = state.spends;
                self.last_action_ns = state.last_action_ns;
                self.actions_used = state.actions_used;
                self.allowed_count += 1;
                Self::emit("action_allowed", &to, amount.0, "ALLOWED", "Action approved by policy");
                let _ = Promise::new(to).transfer(NearToken::from_yoctonear(amount.0));
                ActionResult { ok: true, code: "ALLOWED".into(), message: "Action approved by policy".into() }
            }
            pc::Verdict::Rejected(reason) => {
                // No panic: state change + event must persist as an on-chain receipt.
                self.rejected_count += 1;
                Self::emit("action_rejected", &to, amount.0, reason.code(), reason.message());
                ActionResult { ok: false, code: reason.code().into(), message: reason.message().into() }
            }
        }
    }

    // ───────────────────────── owner-only controls ─────────────────────────

    pub fn allow_recipient(&mut self, recipient: AccountId, cap_per_tx: U128) {
        self.assert_owner();
        self.allowlist.retain(|(a, _)| a != &recipient);
        self.allowlist.push((recipient, cap_per_tx.0));
    }

    pub fn remove_recipient(&mut self, recipient: AccountId) {
        self.assert_owner();
        self.allowlist.retain(|(a, _)| a != &recipient);
    }

    /// Kill switch.
    pub fn pause(&mut self) {
        self.assert_owner();
        self.paused = true;
        env::log_str("EVENT_JSON:{\"standard\":\"agentvault\",\"version\":\"1.0.0\",\"event\":\"paused\",\"data\":[{}]}");
    }

    pub fn unpause(&mut self) {
        self.assert_owner();
        self.paused = false;
    }

    /// Start a fresh agent session (new expiry + usage budget).
    pub fn renew_session(&mut self, session_ttl_secs: u64, max_actions: u32) {
        self.assert_owner();
        self.expires_at_ns = env::block_timestamp().saturating_add(session_ttl_secs * pc::NS_PER_SEC);
        self.max_actions = max_actions;
        self.actions_used = 0;
    }

    pub fn set_limits(&mut self, per_tx_cap: U128, budget: U128, cooldown_secs: u64) {
        self.assert_owner();
        self.per_tx_cap = per_tx_cap.0;
        self.budget = budget.0;
        self.cooldown_ns = cooldown_secs * pc::NS_PER_SEC;
    }

    /// Owner can always pull funds out.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        self.assert_owner();
        Promise::new(self.owner.clone()).transfer(NearToken::from_yoctonear(amount.0))
    }

    // ───────────────────────── views ─────────────────────────

    /// Dry-run: what WOULD the policy say? Used by the off-chain validator,
    /// so there is no second copy of the rules to keep in sync.
    pub fn check_action(&self, to: AccountId, amount: U128) -> ActionResult {
        let v = pc::dry_run(&self.policy(), &self.state(), env::block_timestamp(), self.available(), to.as_str(), amount.0);
        match v {
            pc::Verdict::Allowed => ActionResult { ok: true, code: "ALLOWED".into(), message: "Action would be approved".into() },
            pc::Verdict::Rejected(r) => ActionResult { ok: false, code: r.code().into(), message: r.message().into() },
        }
    }

    pub fn get_policy(&self) -> PolicyView {
        PolicyView {
            owner: self.owner.clone(),
            per_tx_cap: U128(self.per_tx_cap),
            budget: U128(self.budget),
            window_secs: self.window_ns / pc::NS_PER_SEC,
            cooldown_secs: self.cooldown_ns / pc::NS_PER_SEC,
            expires_at_ns: self.expires_at_ns,
            max_actions: self.max_actions,
            paused: self.paused,
            allowlist: self
                .allowlist
                .iter()
                .map(|(a, c)| AllowedRecipient { recipient: a.clone(), cap_per_tx: U128(*c) })
                .collect(),
        }
    }

    pub fn get_stats(&self) -> StatsView {
        StatsView {
            allowed_count: self.allowed_count,
            rejected_count: self.rejected_count,
            actions_used: self.actions_used,
            spent_in_window: U128(self.state().spent_in_window(env::block_timestamp(), self.window_ns)),
            spendable_balance: U128(self.available()),
        }
    }
}

// ───────────────────────── internals ─────────────────────────
impl Vault {
    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }

    fn policy(&self) -> pc::Policy {
        pc::Policy {
            per_tx_cap: self.per_tx_cap,
            budget: self.budget,
            window_ns: self.window_ns,
            cooldown_ns: self.cooldown_ns,
            expires_at_ns: self.expires_at_ns,
            max_actions: self.max_actions,
            paused: self.paused,
            allowlist: self
                .allowlist
                .iter()
                .map(|(a, c)| pc::AllowEntry { recipient: a.to_string(), cap_per_tx: *c })
                .collect(),
        }
    }

    fn state(&self) -> pc::State {
        pc::State {
            spends: self.spends.clone(),
            last_action_ns: self.last_action_ns,
            actions_used: self.actions_used,
        }
    }

    /// Balance the agent may spend: total minus storage stake minus a safety reserve.
    fn available(&self) -> u128 {
        let storage = (env::storage_usage() as u128) * env::storage_byte_cost().as_yoctonear();
        env::account_balance()
            .as_yoctonear()
            .saturating_sub(storage)
            .saturating_sub(RESERVE_YOCTO)
    }

    /// NEP-297 style event. Amounts are strings (u128 does not fit JSON numbers).
    fn emit(event: &str, to: &AccountId, amount: u128, code: &str, message: &str) {
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"agentvault\",\"version\":\"1.0.0\",\"event\":\"{}\",\"data\":[{{\"to\":\"{}\",\"amount\":\"{}\",\"code\":\"{}\",\"message\":\"{}\"}}]}}",
            event, to, amount, code, message
        ));
    }
}
