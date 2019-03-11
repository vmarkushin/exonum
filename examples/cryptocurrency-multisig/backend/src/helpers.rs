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

//! Helpers.

use exonum::crypto::{HashStream, PublicKey, PUBLIC_KEY_LENGTH};

/// Create `PublicKey` for multisignature wallet from parties' `PublicKeys`s
/// by hashing them. In general, the given list of `PublicKey`s should be sorted.
pub fn create_multisig_wallet_pub_key(pub_keys: &Vec<PublicKey>) -> PublicKey {
    let hasher = pub_keys.iter()
        .fold(HashStream::new(), |hs, pk| hs.update(pk.as_ref()));
    let final_hash = hasher.hash();
    PublicKey::from_slice(&final_hash[..PUBLIC_KEY_LENGTH]).unwrap()
}

#[test]
fn test_create_multisig_wallet_pub_key() {
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
        122, 31, 188, 213, 151, 125, 100, 12, 159
    ]);

    assert_eq!(expected_hash, new_pub_key.hash());
}