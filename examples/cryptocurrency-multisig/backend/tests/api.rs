// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! These are tests concerning the API of the cryptocurrency service. See `tx_logic.rs`
//! for tests focused on the business logic of transactions.
//!
//! Note how API tests predominantly use `TestKitApi` to send transactions and make assertions
//! about the storage state.

extern crate exonum;
extern crate exonum_cryptocurrency_multisig as cryptocurrency;
extern crate exonum_testkit;
#[macro_use]
extern crate serde_json;

use exonum::{
    api::node::public::explorer::{TransactionQuery, TransactionResponse},
    crypto::{self, Hash, PublicKey, SecretKey, Signature, sign},
    messages::{self, RawTransaction, Signed},
};
use exonum_testkit::{ApiKind, TestKit, TestKitApi, TestKitBuilder};

// Import data types used in tests from the crate where the service is defined.
use cryptocurrency::{
    api::{WalletInfo, WalletQuery},
    transactions::{CreateWallet, CreateMultiSigWallet, Transfer, MultiSigTransfer},
    wallet::{Wallet, MultiSigWalletInfo},
    Service,
};

// Imports shared test constants.
use constants::{ALICE_NAME, BOB_NAME, MULTISIGNATURE_WALLET_NAME};
use exonum::messages::{ServiceTransaction, BinaryForm};

mod constants;

/// Check that the wallet creation transaction works when invoked via API.
#[test]
fn test_create_wallet() {
    let (mut testkit, api) = create_testkit();
    // Create and send a transaction via API
    let (tx, _) = api.create_wallet(ALICE_NAME);
    testkit.create_block();
    api.assert_tx_status(tx.hash(), &json!({ "type": "success" }));

    // Check that the user indeed is persisted by the service.
    let wallet = api.get_wallet(tx.author()).unwrap();
    assert_eq!(wallet.pub_key, tx.author());
    assert_eq!(wallet.name, ALICE_NAME);
    assert_eq!(wallet.balance, 100);
}

/// Check that the multisignature wallet creation transaction works when invoked via API.
#[test]
fn test_create_multisig_wallet_2_of_2() {
    let (mut testkit, api) = create_testkit();
    // Create and send a transaction via API
    let (tx, _, _, wallet_pub_key) = api.create_multisig_wallet(
        MULTISIGNATURE_WALLET_NAME,
        2, // m (at least 2 signatures need)
        2, // n (parties number)
    );
    testkit.create_block();
    api.assert_tx_status(tx.hash(), &json!({ "type": "success" }));

    // Check that the user indeed is persisted by the service.
    let wallet = api.get_wallet(wallet_pub_key).unwrap();
    assert_eq!(wallet.pub_key, wallet_pub_key);
    assert_eq!(wallet.name, MULTISIGNATURE_WALLET_NAME);
    assert_eq!(wallet.balance, 100);

    let multisig_wallet_data = api.get_multisig_wallet_data(wallet_pub_key).unwrap();
    assert_eq!(multisig_wallet_data.signatures_required, 2);
    assert_eq!(multisig_wallet_data.pub_keys.len(), 2);
}

/// Check that the transfer transaction works as intended.
#[test]
fn test_transfer() {
    // Create 2 wallets.
    let (mut testkit, api) = create_testkit();
    let (tx_alice, key_alice) = api.create_wallet(ALICE_NAME);
    let (tx_bob, _) = api.create_wallet(BOB_NAME);
    testkit.create_block();
    api.assert_tx_status(tx_alice.hash(), &json!({ "type": "success" }));
    api.assert_tx_status(tx_bob.hash(), &json!({ "type": "success" }));

    // Check that the initial Alice's and Bob's balances persisted by the service.
    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 100);
    let wallet = api.get_wallet(tx_bob.author()).unwrap();
    assert_eq!(wallet.balance, 100);

    // Transfer funds by invoking the corresponding API method.
    let tx = Transfer::sign(
        &tx_alice.author(),
        &tx_bob.author(),
        10, // transferred amount
        0,  // seed
        &key_alice,
    );
    api.transfer(&tx);
    testkit.create_block();
    api.assert_tx_status(tx.hash(), &json!({ "type": "success" }));

    // After the transfer transaction is included into a block, we may check new wallet
    // balances.
    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 90);
    let wallet = api.get_wallet(tx_bob.author()).unwrap();
    assert_eq!(wallet.balance, 110);
}

/// Check that a transfer from a non-existing wallet fails as expected.
#[test]
fn test_transfer_from_nonexisting_wallet() {
    let (mut testkit, api) = create_testkit();

    let (tx_alice, key_alice) = api.create_wallet(ALICE_NAME);
    let (tx_bob, _) = api.create_wallet(BOB_NAME);
    // Do not commit Alice's transaction, so Alice's wallet does not exist
    // when a transfer occurs.
    testkit.create_block_with_tx_hashes(&[tx_bob.hash()]);

    api.assert_no_wallet(tx_alice.author());
    let wallet = api.get_wallet(tx_bob.author()).unwrap();
    assert_eq!(wallet.balance, 100);

    let tx = Transfer::sign(
        &tx_alice.author(),
        &tx_bob.author(),
        10, // transfer amount
        0,  // seed
        &key_alice,
    );
    api.transfer(&tx);
    testkit.create_block_with_tx_hashes(&[tx.hash()]);
    api.assert_tx_status(
        tx.hash(),
        &json!({ "type": "error", "code": 1, "description": "Sender doesn't exist" }),
    );

    // Check that Bob's balance doesn't change.
    let wallet = api.get_wallet(tx_bob.author()).unwrap();
    assert_eq!(wallet.balance, 100);
}

/// Check that a transfer to a non-existing wallet fails as expected.
#[test]
fn test_transfer_to_nonexisting_wallet() {
    let (mut testkit, api) = create_testkit();

    let (tx_alice, key_alice) = api.create_wallet(ALICE_NAME);
    let (tx_bob, _) = api.create_wallet(BOB_NAME);
    // Do not commit Bob's transaction, so Bob's wallet does not exist
    // when a transfer occurs.
    testkit.create_block_with_tx_hashes(&[tx_alice.hash()]);

    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 100);
    api.assert_no_wallet(tx_bob.author());

    let tx = Transfer::sign(
        &tx_alice.author(),
        &tx_bob.author(),
        10, // transfer amount
        0,  // seed
        &key_alice,
    );
    api.transfer(&tx);
    testkit.create_block_with_tx_hashes(&[tx.hash()]);
    api.assert_tx_status(
        tx.hash(),
        &json!({ "type": "error", "code": 2, "description": "Receiver doesn't exist" }),
    );

    // Check that Alice's balance doesn't change.
    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 100);
}

/// Check that the multisignature transfer transaction works as intended.
#[test]
fn test_multisig_transfer() {
    // Create 2 wallets (multisig one and simple one).
    let (mut testkit, api) = create_testkit();
    let (tx_multisig,
        pub_keys, keys,
        multisig_pk) = api.create_multisig_wallet(
        MULTISIGNATURE_WALLET_NAME,
        2, // m (at least 2 signatures need)
        3); // n (parties number)
    let (tx_alice, _) = api.create_wallet(ALICE_NAME);
    testkit.create_block();
    api.assert_tx_status(tx_multisig.hash(), &json!({ "type": "success" }));
    api.assert_tx_status(tx_alice.hash(), &json!({ "type": "success" }));

    // Check that the initial Alice's and Bob's balances persisted by the service.
    let wallet = api.get_wallet(multisig_pk).unwrap();
    assert_eq!(wallet.balance, 100);
    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 100);

    let transfer = Transfer {
        to: tx_alice.author().clone(),
        amount: 10,
        seed: 0
    };
    let tx_sender = &pub_keys[0];
    let tx_sender_key = &keys[0];
    let transfer_service_tx: ServiceTransaction = transfer.clone().into();
    let transfer_data = transfer_service_tx.encode().unwrap();
    let tx_signatures: &Vec<Signature> = &(1..3)
        .map(|i| sign(&transfer_data, &keys[i]))
        .collect();
    let tx_pub_keys = Vec::from(&pub_keys[1..3]);

    // Transfer funds by invoking the corresponding API method.
    let tx = MultiSigTransfer::sign(
        tx_sender,
        &multisig_pk,
        &transfer.to,
        &tx_pub_keys,
        tx_signatures,
        transfer.amount,
        transfer.seed,
        tx_sender_key,
    );
    api.transfer(&tx);
    testkit.create_block();
    api.assert_tx_status(tx.hash(), &json!({ "type": "success" }));

    // After the transfer transaction is included into a block, we may check new wallet
    // balances.
    let wallet = api.get_wallet(multisig_pk).unwrap();
    assert_eq!(wallet.balance, 90);
    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 110);
}

/// Check that the multisig transfer transaction with foreign `PublicKey`
/// does not lead to changes in sender's and receiver's balances.
#[test]
fn test_multisig_transfer_with_foreign_pub_key() {
    // Create 2 wallets (multisig one and simple one).
    let (mut testkit, api) = create_testkit();
    let (tx_multisig,
        pub_keys, keys,
        multisig_pk) = api.create_multisig_wallet(
        MULTISIGNATURE_WALLET_NAME,
        2, // m (at least 2 signatures need)
        3); // n (parties number)
    let (tx_alice, _) = api.create_wallet(ALICE_NAME);
    testkit.create_block();
    api.assert_tx_status(tx_multisig.hash(), &json!({ "type": "success" }));
    api.assert_tx_status(tx_alice.hash(), &json!({ "type": "success" }));

    // Check that the initial Alice's and Bob's balances persisted by the service.
    let wallet = api.get_wallet(multisig_pk).unwrap();
    assert_eq!(wallet.balance, 100);
    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 100);

    let transfer = Transfer {
        to: tx_alice.author().clone(),
        amount: 10,
        seed: 0
    };
    let tx_sender = &pub_keys[0];
    let tx_sender_key = &keys[0];
    let transfer_service_tx: ServiceTransaction = transfer.clone().into();
    let transfer_data = transfer_service_tx.encode().unwrap();
    let tx_signatures: &Vec<Signature> = &(1..3)
        .map(|i| sign(&transfer_data, &keys[i]))
        .collect();
    let tx_pub_keys = vec![pub_keys[1].clone(), tx_alice.author().clone()];

    // Transfer funds by invoking the corresponding API method.
    let tx = MultiSigTransfer::sign(
        tx_sender,
        &multisig_pk,
        &transfer.to,
        &tx_pub_keys,
        tx_signatures,
        transfer.amount,
        transfer.seed,
        tx_sender_key,
    );
    api.transfer(&tx);
    testkit.create_block();
    api.assert_tx_status(
        tx.hash(),
        &json!({ "type": "error", "code": 5, "description": "Invalid or duplicated parties' data" })
    );

    // After the transfer transaction is included into a block, we may check new wallet
    // balances.
    let wallet = api.get_wallet(multisig_pk).unwrap();
    assert_eq!(wallet.balance, 100);
    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 100);
}

/// Check that an overcharge does not lead to changes in sender's and receiver's balances.
#[test]
fn test_transfer_overcharge() {
    let (mut testkit, api) = create_testkit();

    let (tx_alice, key_alice) = api.create_wallet(ALICE_NAME);
    let (tx_bob, _) = api.create_wallet(BOB_NAME);
    testkit.create_block();

    // Transfer funds. The transfer amount (110) is more than Alice has (100).
    let tx = Transfer::sign(
        &tx_alice.author(),
        &tx_bob.author(),
        110, // transfer amount
        0,   // seed
        &key_alice,
    );
    api.transfer(&tx);
    testkit.create_block();
    api.assert_tx_status(
        tx.hash(),
        &json!({ "type": "error", "code": 3, "description": "Insufficient currency amount" }),
    );

    let wallet = api.get_wallet(tx_alice.author()).unwrap();
    assert_eq!(wallet.balance, 100);
    let wallet = api.get_wallet(tx_bob.author()).unwrap();
    assert_eq!(wallet.balance, 100);
}

#[test]
fn test_unknown_wallet_request() {
    let (_testkit, api) = create_testkit();

    // Transaction is sent by API, but isn't committed.
    let (tx, _) = api.create_wallet(ALICE_NAME);

    api.assert_no_wallet(tx.author());
}

/// Wrapper for the cryptocurrency service API allowing to easily use it
/// (compared to `TestKitApi` calls).
struct CryptocurrencyApi {
    pub inner: TestKitApi,
}

impl CryptocurrencyApi {
    /// Generates a wallet creation transaction with a random key pair, sends it over HTTP,
    /// and checks the synchronous result (i.e., the hash of the transaction returned
    /// within the response).
    /// Note that the transaction is not immediately added to the blockchain, but rather is put
    /// to the pool of unconfirmed transactions.
    fn create_wallet(&self, name: &str) -> (Signed<RawTransaction>, SecretKey) {
        let (pubkey, key) = crypto::gen_keypair();
        // Create a pre-signed transaction
        let tx = CreateWallet::sign(name, &pubkey, &key);

        let data = messages::to_hex_string(&tx);
        let tx_info: TransactionResponse = self
            .inner
            .public(ApiKind::Explorer)
            .query(&json!({ "tx_body": data }))
            .post("v1/transactions")
            .unwrap();
        assert_eq!(tx_info.tx_hash, tx.hash());
        (tx, key)
    }

    /// Generates a multisignature wallet (M-of-N) creation transaction with a random key pairs,
    /// where M is `at_least` and N is `of_count`. Then sends it over HTTP,
    /// and checks the synchronous result (i.e., the hash of the transaction returned
    /// within the response).
    /// Note that the transaction is not immediately added to the blockchain, but rather is put
    /// to the pool of unconfirmed transactions.
    fn create_multisig_wallet(&self, name: &str, at_least: u32, of_count: u32) -> (Signed<RawTransaction>,
                                                                                   Vec<PublicKey>,
                                                                                   Vec<SecretKey>,
                                                                                   PublicKey) {
        use cryptocurrency::create_multisig_wallet_pub_key;

        let mut keypairs: Vec<(PublicKey, SecretKey)> = (0..of_count).map(|_| crypto::gen_keypair()).collect();
        keypairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        let keypairs_cloned = keypairs.clone();
        let pubkeys: Vec<PublicKey> = keypairs_cloned.into_iter().map(|(p, _)| p).collect();
        let keys: Vec<SecretKey> = keypairs.into_iter().map(|(_, s)| s).collect();

        let wallet_pub_key = create_multisig_wallet_pub_key(&pubkeys);
        let (pubkey, key) = (pubkeys[0], keys[0].clone());

        // Create a pre-signed transaction
        let tx = CreateMultiSigWallet::sign(name, &pubkeys, at_least, &pubkey, &key);

        let data = messages::to_hex_string(&tx);
        let tx_info: TransactionResponse = self
            .inner
            .public(ApiKind::Explorer)
            .query(&json!({ "tx_body": data }))
            .post("v1/transactions")
            .unwrap();
        assert_eq!(tx_info.tx_hash, tx.hash());
        (tx, pubkeys, keys, wallet_pub_key)
    }

    fn get_wallet(&self, pub_key: PublicKey) -> Option<Wallet> {
        let wallet_info = self
            .inner
            .public(ApiKind::Service("cryptocurrency"))
            .query(&WalletQuery { pub_key })
            .get::<WalletInfo>("v1/wallets/info")
            .unwrap();

        let to_wallet = wallet_info.wallet_proof.to_wallet.check().unwrap();
        let wallet = to_wallet
            .all_entries()
            .find(|(ref k, _)| **k == pub_key)
            .and_then(|tuple| tuple.1)
            .cloned();
        wallet
    }

    fn get_multisig_wallet_data(&self, pub_key: PublicKey) -> Option<MultiSigWalletInfo> {
        let wallet_info = self
            .inner
            .public(ApiKind::Service("cryptocurrency"))
            .query(&WalletQuery { pub_key })
            .get::<WalletInfo>("v1/wallets/info")
            .unwrap();

        wallet_info.wallet_multisignature_data
    }

    /// Sends a transfer transaction over HTTP and checks the synchronous result.
    fn transfer(&self, tx: &Signed<RawTransaction>) {
        let data = messages::to_hex_string(&tx);
        let tx_info: TransactionResponse = self
            .inner
            .public(ApiKind::Explorer)
            .query(&json!({ "tx_body": data }))
            .post("v1/transactions")
            .unwrap();
        assert_eq!(tx_info.tx_hash, tx.hash());
    }

    /// Asserts that a wallet with the specified public key is not known to the blockchain.
    fn assert_no_wallet(&self, pub_key: PublicKey) {
        let wallet_info: WalletInfo = self
            .inner
            .public(ApiKind::Service("cryptocurrency"))
            .query(&WalletQuery { pub_key })
            .get("v1/wallets/info")
            .unwrap();

        let to_wallet = wallet_info.wallet_proof.to_wallet.check().unwrap();
        assert!(to_wallet.missing_keys().find(|v| **v == pub_key).is_some())
    }

    /// Asserts that the transaction with the given hash has a specified status.
    fn assert_tx_status(&self, tx_hash: Hash, expected_status: &serde_json::Value) {
        let info: serde_json::Value = self
            .inner
            .public(ApiKind::Explorer)
            .query(&TransactionQuery::new(tx_hash))
            .get("v1/transactions")
            .unwrap();

        if let serde_json::Value::Object(mut info) = info {
            let tx_status = info.remove("status").unwrap();
            assert_eq!(tx_status, *expected_status);
        } else {
            panic!("Invalid transaction info format, object expected");
        }
    }
}

/// Creates a testkit together with the API wrapper defined above.
fn create_testkit() -> (TestKit, CryptocurrencyApi) {
    let testkit = TestKitBuilder::validator().with_service(Service).create();
    let api = CryptocurrencyApi {
        inner: testkit.api(),
    };
    (testkit, api)
}
