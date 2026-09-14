#![cfg(test)]

use super::*;
use soroban_sdk::testutils::storage::Instance as _;
use soroban_sdk::testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{token, IntoVal};

#[test]
fn test_asserter_consumer_can_assert_as_itself_through_tholos() {
    let env = Env::default();

    // Deliberately not using blanket auth mocking past construction: this
    // test exists specifically to prove authorize_as_current_contract
    // grants the real nested auth Tholos's assert_outcome needs for its
    // token transfer, without blanket auth mocking papering over a bug in
    // that mechanism. A brief mock_all_auths_allowing_non_root_auth()
    // covers only __constructor's admin.require_auth() (admin is now
    // pinned atomically at deploy, #158, so there's no way to narrow-mock
    // it before a contract id exists to address a MockAuthInvoke at; the
    // non-root variant is needed because registering from imported WASM
    // records the constructor's auth as non-root). Every call after that,
    // including initialize, mocks only the one specific signature it needs.
    let admin = Address::generate(&env);
    env.mock_all_auths_allowing_non_root_auth();
    let tholos_id = env.register(tholos::WASM, (admin.clone(),));
    let tholos_client = tholos::Client::new(&env, &tholos_id);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_id = token_contract.address();
    let token_asset_client = token::StellarAssetClient::new(&env, &token_id);

    let resolvers = Vec::from_array(
        &env,
        [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ],
    );
    let bond_amount: i128 = 100;

    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &tholos_id,
            fn_name: "initialize",
            args: (
                token_id.clone(),
                bond_amount,
                3600u64,
                resolvers.clone(),
                0u32,
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);
    tholos_client.initialize(&token_id, &bond_amount, &3600, &resolvers, &0u32);

    let consumer_admin = Address::generate(&env);
    env.mock_all_auths_allowing_non_root_auth();
    let consumer_id = env.register(AsserterConsumer, (consumer_admin.clone(),));
    let consumer_client = AsserterConsumerClient::new(&env, &consumer_id);

    env.mock_auths(&[MockAuth {
        address: &consumer_admin,
        invoke: &MockAuthInvoke {
            contract: &consumer_id,
            fn_name: "initialize",
            args: (tholos_id.clone(), token_id.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    consumer_client.initialize(&tholos_id, &token_id);

    // The bond comes from this contract's own balance, not an end user's.
    env.mock_auths(&[MockAuth {
        address: &token_admin,
        invoke: &MockAuthInvoke {
            contract: &token_id,
            fn_name: "mint",
            args: (consumer_id.clone(), 1_000i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    token_asset_client.mint(&consumer_id, &1_000);

    // create_assertion_as_self is admin-gated to prevent arbitrary fund drain (#157)
    env.mock_auths(&[MockAuth {
        address: &consumer_admin,
        invoke: &MockAuthInvoke {
            contract: &consumer_id,
            fn_name: "create_assertion_as_self",
            args: (bond_amount, true).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    let id = consumer_client.create_assertion_as_self(&bond_amount, &true);

    let state = consumer_client.get_status(&id);
    assert!(state.outcome);
    assert_eq!(state.asserter, consumer_id);
    assert_eq!(
        token::Client::new(&env, &token_id).balance(&consumer_id),
        900
    );
    assert_eq!(token::Client::new(&env, &token_id).balance(&tholos_id), 100);
}

/// A registered token, resolver committee, Tholos instance, and AsserterConsumer.
struct Fixture {
    env: Env,
    tholos_id: Address,
    tholos_client: tholos::Client<'static>,
    token_id: Address,
    consumer_id: Address,
    consumer_client: AsserterConsumerClient<'static>,
    resolvers: Vec<Address>,
    bond_amount: i128,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();

        // Covers __constructor's admin.require_auth(): admin is pinned
        // atomically at deploy (#157, #158), so it applies to registration
        // itself, before initialize_tholos()'s own mock_all_auths() runs.
        env.mock_all_auths_allowing_non_root_auth();
        let tholos_admin = Address::generate(&env);
        let tholos_id = env.register(tholos::WASM, (tholos_admin,));
        let tholos_client = tholos::Client::new(&env, &tholos_id);

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();

        let resolvers = Vec::from_array(
            &env,
            [
                Address::generate(&env),
                Address::generate(&env),
                Address::generate(&env),
            ],
        );

        let consumer_admin = Address::generate(&env);
        let consumer_id = env.register(AsserterConsumer, (consumer_admin,));
        let consumer_client = AsserterConsumerClient::new(&env, &consumer_id);

        Fixture {
            env,
            tholos_id,
            tholos_client,
            token_id,
            consumer_id,
            consumer_client,
            resolvers,
            bond_amount: 100,
        }
    }

    fn initialize_tholos(&self) {
        self.env.mock_all_auths();
        self.tholos_client.initialize(
            &self.token_id,
            &self.bond_amount,
            &3600,
            &self.resolvers,
            &0u32,
        );
    }

    fn initialize_consumer(&self) {
        self.env.mock_all_auths();
        self.consumer_client
            .initialize(&self.tholos_id, &self.token_id);
    }

    fn initialize_all(&self) {
        self.initialize_tholos();
        self.initialize_consumer();
    }
}

#[test]
fn test_cannot_initialize_twice_and_preserves_trusted_configuration() {
    let f = Fixture::new();
    f.initialize_all();

    let token_contract = token::StellarAssetClient::new(&f.env, &f.token_id);
    f.env.mock_all_auths();
    token_contract.mint(&f.consumer_id, &1_000);

    // Attacker attempts to overwrite trusted targets via a second initialize call
    let attacker_tholos = Address::generate(&f.env);
    let attacker_token = Address::generate(&f.env);
    assert_eq!(
        f.consumer_client
            .try_initialize(&attacker_tholos, &attacker_token),
        Err(Ok(Error::AlreadyInitialized))
    );

    // Verify original configuration is unchanged and bond is paid to tholos_id
    let id = f
        .consumer_client
        .create_assertion_as_self(&f.bond_amount, &true);

    let token_client = token::Client::new(&f.env, &f.token_id);
    assert_eq!(token_client.balance(&f.consumer_id), 900);
    assert_eq!(token_client.balance(&f.tholos_id), 100);
    assert_eq!(token_client.balance(&attacker_tholos), 0);

    let state = f.consumer_client.get_status(&id);
    assert_eq!(state.asserter, f.consumer_id);
    assert!(state.outcome);
}

#[test]
fn test_instance_storage_ttl_is_extended_by_create_assertion() {
    let f = Fixture::new();
    f.initialize_all();

    let token_contract = token::StellarAssetClient::new(&f.env, &f.token_id);
    f.env.mock_all_auths();
    token_contract.mint(&f.consumer_id, &1_000);

    let instance_ttl = || {
        f.env
            .as_contract(&f.consumer_id, || f.env.storage().instance().get_ttl())
    };

    assert_eq!(instance_ttl(), INSTANCE_BUMP_AMOUNT);

    // Advance ledger close to expiry and verify assertion bumps TTL back to INSTANCE_BUMP_AMOUNT
    f.env
        .ledger()
        .with_mut(|l| l.sequence_number += INSTANCE_BUMP_AMOUNT - 10);

    f.consumer_client
        .create_assertion_as_self(&f.bond_amount, &true);
    assert_eq!(instance_ttl(), INSTANCE_BUMP_AMOUNT);
}

#[test]
fn test_create_assertion_as_self_fails_before_initialization() {
    let f = Fixture::new();
    f.env.mock_all_auths();

    assert_eq!(
        f.consumer_client
            .try_create_assertion_as_self(&f.bond_amount, &true),
        Err(Ok(Error::NotInitialized))
    );
}

#[test]
fn test_get_status_fails_before_initialization() {
    let f = Fixture::new();
    assert_eq!(
        f.consumer_client.try_get_status(&0),
        Err(Ok(Error::NotInitialized))
    );
}

#[test]
fn test_create_assertion_as_self_fails_against_uninitialized_tholos() {
    let f = Fixture::new();
    f.initialize_consumer();
    f.env.mock_all_auths();

    // No initialize() call on Tholos: Tholos rejects with NotInitialized before ever
    // reaching the token transfer, so this doesn't need mocked auths either.
    assert_eq!(
        f.consumer_client
            .try_create_assertion_as_self(&f.bond_amount, &true),
        Err(Ok(Error::TholosNotInitialized))
    );
}

#[test]
fn test_create_assertion_as_self_fails_when_tholos_paused() {
    let f = Fixture::new();
    f.initialize_all();

    f.env.mock_all_auths();
    f.tholos_client.set_paused(&true);

    assert_eq!(
        f.consumer_client
            .try_create_assertion_as_self(&f.bond_amount, &true),
        Err(Ok(Error::TholosPaused))
    );
}

#[test]
fn test_create_assertion_as_self_fails_for_invalid_tholos_id() {
    let env = Env::default();
    env.mock_all_auths();
    let not_a_tholos_instance = Address::generate(&env);
    let token_id = Address::generate(&env);
    let admin = Address::generate(&env);

    let consumer_id = env.register(AsserterConsumer, (admin,));
    let consumer_client = AsserterConsumerClient::new(&env, &consumer_id);
    consumer_client.initialize(&not_a_tholos_instance, &token_id);

    let result = consumer_client.try_create_assertion_as_self(&100, &true);
    assert_eq!(result, Err(Ok(Error::InvalidTholosId)));
}

#[test]
fn test_get_status_fails_for_nonexistent_assertion() {
    let f = Fixture::new();
    f.initialize_all();

    assert_eq!(
        f.consumer_client.try_get_status(&999),
        Err(Ok(Error::AssertionNotFound))
    );
}

#[test]
fn test_get_status_fails_for_invalid_tholos_id() {
    let env = Env::default();
    env.mock_all_auths();
    let not_a_tholos_instance = Address::generate(&env);
    let token_id = Address::generate(&env);
    let admin = Address::generate(&env);

    let consumer_id = env.register(AsserterConsumer, (admin,));
    let consumer_client = AsserterConsumerClient::new(&env, &consumer_id);
    consumer_client.initialize(&not_a_tholos_instance, &token_id);

    let result = consumer_client.try_get_status(&0);
    assert_eq!(result, Err(Ok(Error::InvalidTholosId)));
}

#[test]
#[should_panic]
fn test_create_assertion_as_self_rejects_unauthorized_caller() {
    let f = Fixture::new();
    f.initialize_all();

    let attacker = Address::generate(&f.env);
    f.consumer_client
        .mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &f.consumer_id,
                fn_name: "create_assertion_as_self",
                args: (f.bond_amount, true).into_val(&f.env),
                sub_invokes: &[],
            },
        }])
        .create_assertion_as_self(&f.bond_amount, &true);
}

#[test]
#[should_panic]
fn test_create_assertion_as_self_rejects_missing_auth() {
    let f = Fixture::new();
    f.initialize_all();

    f.consumer_client
        .mock_auths(&[])
        .create_assertion_as_self(&f.bond_amount, &true);
}

#[test]
#[should_panic]
fn test_initialize_rejects_caller_without_admin_auth() {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let tholos_id = Address::generate(&env);
    let token_id = Address::generate(&env);

    let consumer_id = env.register(AsserterConsumer, (admin,));
    let consumer_client = AsserterConsumerClient::new(&env, &consumer_id);

    consumer_client
        .mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &consumer_id,
                fn_name: "initialize",
                args: (tholos_id.clone(), token_id.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .initialize(&tholos_id, &token_id);
}

#[test]
#[should_panic]
fn test_constructor_requires_admin_auth() {
    let env = Env::default();
    let admin = Address::generate(&env);

    // Register without providing admin authorization; __constructor's require_auth must reject and panic.
    let _ = env.register(AsserterConsumer, (admin,));
}
