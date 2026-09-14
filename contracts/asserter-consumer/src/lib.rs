#![no_std]

//! Second integration example: this contract's own address as the asserter,
//! demonstrating the "Your contract's own address as asserter" pattern from
//! INTEGRATION.md. See `demo-consumer` for the simpler, recommended default
//! (end user as asserter) instead.

use soroban_sdk::{
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    contract, contractimpl, contracttype, Address, Env, IntoVal, Symbol, Vec,
};
use tholos_client::{tholos, Error};

#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DataKey {
    Admin,
    Tholos,
    Token,
}

const DAY_IN_LEDGERS: u32 = 17280;
const INSTANCE_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const INSTANCE_LIFETIME_THRESHOLD: u32 = INSTANCE_BUMP_AMOUNT - DAY_IN_LEDGERS;

#[contract]
pub struct AsserterConsumer;

#[contractimpl]
impl AsserterConsumer {
    /// Pins `admin` atomically with contract creation. Soroban invokes a
    /// contract's constructor (a function literally named `__constructor`)
    /// as part of the same `CreateContractV2` host operation that creates
    /// the instance, and the host will not accept a separate, later
    /// invocation of it: no other transaction can ever execute in between
    /// "this contract now exists" and "its admin is recorded", so unlike a
    /// deploy-then-call-`initialize(admin)` two-step, there is no window
    /// for a third party watching the mempool to submit their own call
    /// first and become admin of an instance someone else paid to deploy
    /// (#157, #158). The rest of the deployment-wide config is pinned by a
    /// separate `initialize` call below, which authenticates against the
    /// admin fixed here.
    pub fn __constructor(env: Env, admin: Address) {
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        Self::touch_instance_ttl(&env);
    }

    /// One-time initialization pinning the trusted Tholos instance and
    /// underlying bond token.
    ///
    /// Requires authorization from the stored `admin` pinned at constructor
    /// time. Fails with `AlreadyInitialized` if called more than once, or
    /// `NotInitialized` if called on an unconstructed instance.
    pub fn initialize(env: Env, tholos_id: Address, token_id: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Tholos) {
            return Err(Error::AlreadyInitialized);
        }
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::Tholos, &tholos_id);
        env.storage().instance().set(&DataKey::Token, &token_id);
        Self::touch_instance_ttl(&env);

        Ok(())
    }

    /// Posts an assertion with this contract's own address as the asserter, so
    /// the bond pools under this contract rather than an end user.
    ///
    /// Uses the trusted `tholos_id` and `token_id` pinned at `initialize`.
    /// `bond_amount` must match the Tholos instance's actual configuration at
    /// `tholos_id`: there's no way to query it from Tholos ahead of the call,
    /// so the caller (or this contract's own deployer) has to already know it,
    /// exactly as INTEGRATION.md describes.
    ///
    /// To prevent arbitrary callers from draining this contract's balance via
    /// self-authorized transfers (#157), this entrypoint is restricted to the
    /// configured `admin` (`admin.require_auth()`).
    ///
    /// Soroban only auto-grants a contract's implicit self-authorization one
    /// call deep. This call chain is two deep (this contract -> Tholos ->
    /// the token's `transfer`), so the deeper call needs to be explicitly
    /// pre-authorized with `authorize_as_current_contract` before invoking
    /// Tholos, specifying the exact token contract, `transfer` args, and
    /// amount Tholos will end up calling.
    ///
    /// Returns `Error::NotInitialized` if this contract has not been initialized,
    /// `Error::TholosNotInitialized` or `Error::TholosPaused` if the Tholos
    /// instance can't currently accept an assertion, or `Error::InvalidTholosId`
    /// if the pinned `tholos_id` doesn't resolve to an invokable Tholos instance at all.
    pub fn create_assertion_as_self(
        env: Env,
        bond_amount: i128,
        outcome: bool,
    ) -> Result<u64, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();
        Self::touch_instance_ttl(&env);

        let tholos_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::Tholos)
            .ok_or(Error::NotInitialized)?;
        let token_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;

        let curr_contract = env.current_contract_address();

        env.authorize_as_current_contract(Vec::from_array(
            &env,
            [InvokerContractAuthEntry::Contract(SubContractInvocation {
                context: ContractContext {
                    contract: token_id,
                    fn_name: Symbol::new(&env, "transfer"),
                    args: Vec::from_array(
                        &env,
                        [
                            curr_contract.into_val(&env),
                            tholos_id.into_val(&env),
                            bond_amount.into_val(&env),
                        ],
                    ),
                },
                sub_invocations: Vec::new(&env),
            })],
        ));

        let client = tholos::Client::new(&env, &tholos_id);
        Error::from_tholos_call(client.try_assert_outcome(&curr_contract, &outcome))
    }

    /// Forwards a read of an assertion's current state from the pinned Tholos
    /// instance. See INTEGRATION.md for why `Assertion.outcome` is the
    /// *claimed* outcome, not necessarily the final one if the assertion was
    /// disputed and overturned.
    ///
    /// Returns `Error::NotInitialized` if this contract has not been initialized,
    /// `Error::AssertionNotFound` if no assertion exists under `id` on the
    /// Tholos instance, or `Error::InvalidTholosId` if the pinned `tholos_id`
    /// doesn't resolve to an invokable Tholos instance at all.
    pub fn get_status(env: Env, id: u64) -> Result<tholos::Assertion, Error> {
        let tholos_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::Tholos)
            .ok_or(Error::NotInitialized)?;
        let client = tholos::Client::new(&env, &tholos_id);
        Error::from_tholos_call(client.try_get_assertion_state(&id))
    }

    fn touch_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
}

mod test;
