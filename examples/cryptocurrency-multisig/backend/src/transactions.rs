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

//! Cryptocurrency transactions.

// Workaround for `failure` see https://github.com/rust-lang-nursery/failure/issues/223 and
// ECR-1771 for the details.
#![allow(bare_trait_objects)]

use exonum::{
    blockchain::{ExecutionError, ExecutionResult, Transaction, TransactionContext},
    crypto::{PublicKey, SecretKey, Signature},
    messages::{Message, RawTransaction, Signed},
};

use super::proto;
use schema::Schema;
use CRYPTOCURRENCY_SERVICE_ID;

const ERROR_SENDER_SAME_AS_RECEIVER: u8 = 0;

/// Error codes emitted by wallet transactions during execution.
#[derive(Debug, Fail)]
#[repr(u8)]
pub enum Error {
    /// Wallet already exists.
    ///
    /// Can be emitted by `CreateWallet`.
    #[fail(display = "Wallet already exists")]
    WalletAlreadyExists = 0,

    /// Sender doesn't exist.
    ///
    /// Can be emitted by `Transfer`.
    #[fail(display = "Sender doesn't exist")]
    SenderNotFound = 1,

    /// Receiver doesn't exist.
    ///
    /// Can be emitted by `Transfer` or `Issue`.
    #[fail(display = "Receiver doesn't exist")]
    ReceiverNotFound = 2,

    /// Insufficient currency amount.
    ///
    /// Can be emitted by `Transfer`.
    #[fail(display = "Insufficient currency amount")]
    InsufficientCurrencyAmount = 3,

    /// Number of given parties' signatures and public keys mismatch.
    ///
    /// Can be emitted by `MultiSigTransfer`.
    #[fail(display = "Number of given parties' signatures and public keys mismatch")]
    NumberOfSignaturesAndPublicKeysMismatch = 4,

    /// Invalid or duplicated parties' data.
    ///
    /// Can be emitted by `MultiSigTransfer`.
    #[fail(display = "Invalid or duplicated parties' data")]
    InvalidOrDuplicatedPartiesData = 5,

    /// Number of given signatures is less than required.
    ///
    /// Can be emitted by `MultiSigTransfer`.
    #[fail(display = "Number of given signatures is less than required")]
    NotEnoughSignatures = 6,

    /// Attempt to do simple transfer from multisig wallet. Use MultiSigTransfer instead.
    ///
    /// Can be emitted by `Transfer`.
    #[fail(display = "Attempt to do simple transfer from multisig wallet. Use MultiSigTransfer instead")]
    SimpleTransferFromMultiSigWallet = 7,

    /// Quorum is greater than parties number.
    ///
    /// Can be emitted by `CreateMultiSigWallet`.
    #[fail(display = "Quorum is greater than parties number")]
    QuorumIsGreaterThanPartiesNumber = 8,
}

impl From<Error> for ExecutionError {
    fn from(value: Error) -> ExecutionError {
        let description = format!("{}", value);
        ExecutionError::with_description(value as u8, description)
    }
}

/// Transfer `amount` of the currency from one wallet to another.
#[derive(Clone, Debug, ProtobufConvert)]
#[exonum(pb = "proto::Transfer", serde_pb_convert)]
pub struct Transfer {
    /// `PublicKey` of receiver's wallet.
    pub to: PublicKey,
    /// Amount of currency to transfer.
    pub amount: u64,
    /// Auxiliary number to guarantee [non-idempotence][idempotence] of transactions.
    ///
    /// [idempotence]: https://en.wikipedia.org/wiki/Idempotence
    pub seed: u64,
}

/// Transfer `amount` of the currency from one multisignature wallet to another.
/// Require at least `m` signatures of `n` parties of the given multisignature wallet
/// in order to make transfer.
#[derive(Clone, Debug, ProtobufConvert)]
#[exonum(pb = "proto::MultiSigTransfer", serde_pb_convert)]
pub struct MultiSigTransfer {
    /// `PublicKey` of multisig wallet.
    pub from: PublicKey,
    /// `Transfer` data.
    pub transfer: Transfer,
    /// List of `PublicKey`s signed the transfer.
    pub pub_keys: Vec<PublicKey>,
    /// List of `Signatures`s used for the transfer.
    pub signatures: Vec<Vec<u8>>,
}

/// Issue `amount` of the currency to the `wallet`.
#[derive(Serialize, Deserialize, Clone, Debug, ProtobufConvert)]
#[exonum(pb = "proto::Issue")]
pub struct Issue {
    /// Issued amount of currency.
    pub amount: u64,
    /// Auxiliary number to guarantee [non-idempotence][idempotence] of transactions.
    ///
    /// [idempotence]: https://en.wikipedia.org/wiki/Idempotence
    pub seed: u64,
}

/// Create wallet with the given `name`.
#[derive(Serialize, Deserialize, Clone, Debug, ProtobufConvert)]
#[exonum(pb = "proto::CreateWallet")]
pub struct CreateWallet {
    /// Name of the new wallet.
    pub name: String,
}

/// Create multisignature wallet with the given `name`, `quorum`, `public_keys`.
#[derive(Serialize, Deserialize, Clone, Debug, ProtobufConvert)]
#[exonum(pb = "proto::CreateMultiSigWallet")]
pub struct CreateMultiSigWallet {
    /// Name of the new wallet.
    pub name: String,
    /// Minimum number of signatures required to use the wallet.
    pub quorum: u32,
    /// Parties' `PublicKey`s, that can use the wallet.
    pub public_keys: Vec<PublicKey>,
}

/// Transaction group.
#[derive(Serialize, Deserialize, Clone, Debug, TransactionSet)]
pub enum WalletTransactions {
    /// Transfer tx.
    Transfer(Transfer),
    /// MultiSigTransfer tx.
    MultiSigTransfer(MultiSigTransfer),
    /// Issue tx.
    Issue(Issue),
    /// CreateWallet tx.
    CreateWallet(CreateWallet),
    /// CreateMultiSigWallet tx.
    CreateMultiSigWallet(CreateMultiSigWallet),
}

impl CreateWallet {
    #[doc(hidden)]
    pub fn sign(name: &str, pk: &PublicKey, sk: &SecretKey) -> Signed<RawTransaction> {
        Message::sign_transaction(
            Self {
                name: name.to_owned(),
            },
            CRYPTOCURRENCY_SERVICE_ID,
            *pk,
            sk,
        )
    }
}

impl CreateMultiSigWallet {
    #[doc(hidden)]
    pub fn sign(name: &str, public_keys: &Vec<PublicKey>, quorum: u32, pk: &PublicKey, sk: &SecretKey) -> Signed<RawTransaction> {
        Message::sign_transaction(
            Self {
                name: name.to_owned(),
                quorum,
                public_keys: public_keys.clone(),
            },
            CRYPTOCURRENCY_SERVICE_ID,
            *pk,
            sk,
        )
    }
}

impl Transfer {
    #[doc(hidden)]
    pub fn sign(
        pk: &PublicKey,
        &to: &PublicKey,
        amount: u64,
        seed: u64,
        sk: &SecretKey,
    ) -> Signed<RawTransaction> {
        Message::sign_transaction(
            Self { to, amount, seed },
            CRYPTOCURRENCY_SERVICE_ID,
            *pk,
            sk,
        )
    }
}

impl MultiSigTransfer {
    #[doc(hidden)]
    pub fn sign(
        pk: &PublicKey,
        &from: &PublicKey,
        &to: &PublicKey,
        pub_keys: &Vec<PublicKey>,
        signatures: &Vec<Signature>,
        amount: u64,
        seed: u64,
        sk: &SecretKey,
    ) -> Signed<RawTransaction> {
        let serialized_signatures: Vec<Vec<u8>> = signatures.iter()
            .map(|x| Vec::from(x.as_ref()))
            .collect();
        Message::sign_transaction(
            Self {
                from,
                transfer: Transfer { to, amount, seed },
                pub_keys: pub_keys.clone(),
                signatures: serialized_signatures
            },
            CRYPTOCURRENCY_SERVICE_ID,
            *pk,
            sk,
        )
    }
}

impl Transaction for Transfer {
    fn execute(&self, mut context: TransactionContext) -> ExecutionResult {
        let from = &context.author();
        let hash = context.tx_hash();

        let mut schema = Schema::new(context.fork());

        let to = &self.to;
        let amount = self.amount;

        if from == to {
            return Err(ExecutionError::new(ERROR_SENDER_SAME_AS_RECEIVER));
        }

        let sender = schema.wallet(from).ok_or(Error::SenderNotFound)?;
        if schema.multisig_wallet_info(from).is_some() {
            Err(Error::SimpleTransferFromMultiSigWallet)?
        }

        let receiver = schema.wallet(to).ok_or(Error::ReceiverNotFound)?;

        if sender.balance < amount {
            Err(Error::InsufficientCurrencyAmount)?
        }

        schema.decrease_wallet_balance(sender, amount, &hash);
        schema.increase_wallet_balance(receiver, amount, &hash);

        Ok(())
    }
}

impl Transaction for MultiSigTransfer {
    fn execute(&self, mut context: TransactionContext) -> ExecutionResult {
        use exonum::crypto::verify;
        use exonum::messages::{ServiceTransaction, BinaryForm};
        use std::collections::HashSet;

        let from = &self.from;
        let to = &self.transfer.to;

        if from == to {
            return Err(ExecutionError::new(ERROR_SENDER_SAME_AS_RECEIVER));
        }

        // Construct signatures from bytes and remove duplicates
        let mut signatures: Vec<Signature> = self.signatures.iter()
            .filter_map(|b| Signature::from_slice(&b))
            .collect();
        signatures.dedup();

        let public_keys = &self.pub_keys;
        if signatures.len() != public_keys.len() {
            Err(Error::NumberOfSignaturesAndPublicKeysMismatch)?
        }

        let hash = context.tx_hash();

        // Check minimum required number of signatures
        let mut schema = Schema::new(context.fork());
        let multisig_info = schema.multisig_wallet_info(from).ok_or(Error::SenderNotFound)?;
        if signatures.len() < multisig_info.quorum as usize {
            Err(Error::NotEnoughSignatures)?
        }

        // Check all the given keys are belong to the given wallet
        let wallet_pub_keys_set: HashSet<PublicKey> = multisig_info.pub_keys.clone().into_iter().collect();
        let received_pub_keys_set: HashSet<PublicKey>= public_keys.clone().into_iter().collect();
        let intersection_len = wallet_pub_keys_set.intersection(&received_pub_keys_set).collect::<Vec<_>>().len();
        if intersection_len != public_keys.len() {
            Err(Error::InvalidOrDuplicatedPartiesData)?
        }

        let amount = self.transfer.amount;
        let transfer: ServiceTransaction = self.transfer.clone().into();
        let transfer_data = transfer.encode().unwrap();

        for (sig, pub_key) in signatures.iter().zip(public_keys.iter()) {
            if !verify(sig, &transfer_data, pub_key) {
                Err(Error::InvalidOrDuplicatedPartiesData)?
            }
        }

        let sender = schema.wallet(from).ok_or(Error::SenderNotFound)?;
        let receiver = schema.wallet(to).ok_or(Error::ReceiverNotFound)?;
        if sender.balance < amount {
            Err(Error::InsufficientCurrencyAmount)?
        }

        schema.decrease_wallet_balance(sender, amount, &hash);
        schema.increase_wallet_balance(receiver, amount, &hash);

        Ok(())
    }
}

impl Transaction for Issue {
    fn execute(&self, mut context: TransactionContext) -> ExecutionResult {
        let pub_key = &context.author();
        let hash = context.tx_hash();

        let mut schema = Schema::new(context.fork());

        if let Some(wallet) = schema.wallet(pub_key) {
            let amount = self.amount;
            schema.increase_wallet_balance(wallet, amount, &hash);
            Ok(())
        } else {
            Err(Error::ReceiverNotFound)?
        }
    }
}

impl Transaction for CreateWallet {
    fn execute(&self, mut context: TransactionContext) -> ExecutionResult {
        let pub_key = &context.author();
        let hash = context.tx_hash();

        let mut schema = Schema::new(context.fork());

        if schema.wallet(pub_key).is_none() {
            let name = &self.name;
            schema.create_wallet(pub_key, name, &hash);
            Ok(())
        } else {
            Err(Error::WalletAlreadyExists)?
        }
    }
}

impl Transaction for CreateMultiSigWallet {
    fn execute(&self, mut context: TransactionContext) -> ExecutionResult {
        use crate::helpers::create_multisig_wallet_pub_key;
        let quorum = self.quorum;

        if quorum as usize > self.public_keys.len() {
            Err(Error::QuorumIsGreaterThanPartiesNumber)?
        }

        let pub_keys = &self.public_keys;
        let pub_key = &create_multisig_wallet_pub_key(pub_keys);
        let hash = context.tx_hash();

        let mut schema = Schema::new(context.fork());

        if schema.wallet(pub_key).is_none() && schema.multisig_wallet_info(pub_key).is_none() {
            let name = &self.name;
            schema.create_multisig_wallet(name, quorum, pub_keys, &hash);
            Ok(())
        } else {
            Err(Error::WalletAlreadyExists)?
        }
    }
}
