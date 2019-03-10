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

//! Cryptocurrency implementation example using [exonum](http://exonum.com/).

#![deny(
    missing_debug_implementations,
    missing_docs,
    unsafe_code,
    bare_trait_objects
)]

extern crate exonum;
#[macro_use]
extern crate exonum_derive;
extern crate protobuf;
#[macro_use]
extern crate failure;
extern crate serde;
#[macro_use]
extern crate serde_derive;

pub use schema::Schema;

pub mod api;
pub mod proto;
pub mod schema;
pub mod transactions;
pub mod wallet;

use exonum::{
    api::ServiceApiBuilder,
    blockchain::{self, Transaction, TransactionSet},
    crypto::Hash,
    helpers::fabric::{self, Context},
    messages::RawTransaction,
    storage::Snapshot,
};

use exonum::crypto::{HashStream, PublicKey, PUBLIC_KEY_LENGTH};

use transactions::WalletTransactions;

/// Unique service ID.
const CRYPTOCURRENCY_SERVICE_ID: u16 = 128;
/// Name of the service.
const SERVICE_NAME: &str = "cryptocurrency";
/// Initial balance of the wallet.
const INITIAL_BALANCE: u64 = 100;

/// Exonum `Service` implementation.
#[derive(Default, Debug)]
pub struct Service;

impl blockchain::Service for Service {
    fn service_id(&self) -> u16 {
        CRYPTOCURRENCY_SERVICE_ID
    }

    fn service_name(&self) -> &str {
        SERVICE_NAME
    }

    fn state_hash(&self, view: &dyn Snapshot) -> Vec<Hash> {
        let schema = Schema::new(view);
        schema.state_hash()
    }

    fn tx_from_raw(&self, raw: RawTransaction) -> Result<Box<dyn Transaction>, failure::Error> {
        WalletTransactions::tx_from_raw(raw).map(Into::into)
    }

    fn wire_api(&self, builder: &mut ServiceApiBuilder) {
        api::PublicApi::wire(builder);
    }
}

/// A configuration service creator for the `NodeBuilder`.
#[derive(Debug)]
pub struct ServiceFactory;

impl fabric::ServiceFactory for ServiceFactory {
    fn service_name(&self) -> &str {
        SERVICE_NAME
    }

    fn make_service(&mut self, _: &Context) -> Box<dyn blockchain::Service> {
        Box::new(Service)
    }
}

/// Create `PublicKey` for multisignature wallet from parties' `PublicKeys`s
/// by hashing them. In general, the given list of `PublicKey`s should be sorted.
pub fn create_multisig_wallet_pub_key(pub_keys: &Vec<PublicKey>) -> PublicKey {
    let hasher = pub_keys.iter()
        .fold(HashStream::new(), |hs, pk| hs.update(pk.as_ref()));
    let final_hash = hasher.hash();
    let mut pub_key_data = [0u8; PUBLIC_KEY_LENGTH];
    pub_key_data.copy_from_slice(&final_hash[..PUBLIC_KEY_LENGTH]);
    PublicKey::new(pub_key_data)
}

#[test]
fn test_create_multisig_address() {
    use exonum::crypto::CryptoHash;

    let pub_keys = vec![
        PublicKey::new([3; PUBLIC_KEY_LENGTH]),
        PublicKey::new([7; PUBLIC_KEY_LENGTH]),
        PublicKey::new([9; PUBLIC_KEY_LENGTH]),
        PublicKey::new([15; PUBLIC_KEY_LENGTH]),
    ];

    let new_pub_key = create_multisig_wallet_pub_key(&pub_keys);
    let expected_hash = exonum::crypto::hash(&[
        155, 39, 151, 123, 24, 26, 74, 31, 84, 189, 196, 245,
        229, 51, 203, 61, 176, 212, 166, 122, 30, 114, 57,
        122, 31, 188, 213, 151, 125, 100, 12, 159]);

    assert_eq!(expected_hash, new_pub_key.hash());
}