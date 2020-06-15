// Copyright 2017-2020 Social Technologies Ltd.
// This file is part of Substrate.

//! # Decentralized Identifier Pallet
//!
//! A simple FRAME pallet for decentralized identifier registration
//! lookup and storage.
//!
//! \# References
//!
//! https://w3c.github.io/did-core/

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{
	dispatch::DispatchResult, decl_module, decl_storage, decl_event, Parameter, StorageMap,
	traits::{Get},
};
use sp_std::prelude::*;
use frame_system::{self as system, ensure_signed};
use codec::{Codec};
use sp_runtime::traits::Member;

/// Did pallet's configuration trait. All types and constants go in here. If the
/// pallet is dependent on specific other pallets, then their configuration traits
/// should be added to our implied traits list.
pub trait Trait: pallet_balances::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	// Did signing events
	type PublicSigningKey: Parameter + Member + Codec + Default;
	type PublicBoxKey: Parameter + Member + Codec + Default;
}

// A macro for the Storage trait, and its implementation, for this pallet.
// This allows for type-safe usage of the Substrate storage database, so you can
// keep things around between blocks.
decl_storage! {
	trait Store for Module<T: Trait> as DID {
		// Map of DIDs -> (public-signing-key, public-encryption-key, did-reference?)?
		DIDs get(fn dids) config(): map hasher(blake2_128_concat) T::AccountId => Option<(T::PublicSigningKey, T::PublicBoxKey, Option<Vec<u8>>)>;
	}
}

decl_event!(
	/// Events are a simple means of reporting specific conditions and
	/// circumstances that have happened that users, Dapps and/or chain explorers would find
	/// interesting and otherwise difficult to detect.
	pub enum Event<T> where <T as frame_system::Trait>::AccountId {
		DidCreated(AccountId),
		DidRemoved(AccountId),
	}
);

// The module declaration. This states the entry points that we handle. The
// macro takes care of the marshalling of arguments and dispatch.
//
// Anyone can have these functions execute by signing and submitting
// an extrinsic. Ensure that calls into each of these execute in a time, memory and
// using storage space proportional to any costs paid for by the caller or otherwise the
// difficulty of forcing the call to happen.
decl_module! {
	// Simple declaration of the `Module` type. Lets the macro know what its working on.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		/// Deposit one of this pallet's events by using the default implementation.
		/// It is also possible to provide a custom implementation.
		fn deposit_event() = default;

		// Adds a DID on chain TODO: update weights
		/// ---------------------
		/// - Base Weight:
		///     - Creating: 27.56 µs
		///     - Killing: 35.11 µs
		/// - DB Weight: 1 Read, 1 Write to `dids`
		/// # </weight>
		#[weight = T::DbWeight::get().reads_writes(1, 1) + 35_000_000]
		pub fn add(origin, sign_key: T::PublicSigningKey, box_key: T::PublicBoxKey, doc_ref: Option<Vec<u8>>) -> DispatchResult {

			// origin of the transaction needs to be a signed sender account
			let sender = ensure_signed(origin)?;

			// Add DID to the storage
			<DIDs<T>>::insert(sender.clone(), (sign_key, box_key, doc_ref));

			// Deposit an event that the DID has been created
			Self::deposit_event(RawEvent::DidCreated(sender));

			// All good
			Ok(())
		}

		/// Removes a DID from chain storage TODO: update weights
		/// ---------------------
		/// - Base Weight:
		///     - Creating: 27.56 µs
		///     - Killing: 35.11 µs
		/// - DB Weight: 1 Read, 1 Write to `dids`
		/// # </weight>
		#[weight = T::DbWeight::get().reads_writes(1, 1) + 35_000_000]
		pub fn remove(origin) -> DispatchResult {

			// Origin of the transaction needs to be a signed sender account
			let sender = ensure_signed(origin)?;

			// Remove a DID from storage
			<DIDs<T>>::remove(sender.clone());

			// Deposit an event that the DID has been removed
			Self::deposit_event(RawEvent::DidRemoved(sender));

			// All good
			Ok(())
		}

		// The signature could also look like: `fn on_finalize()`
		fn on_finalize(_n: T::BlockNumber) {
			// Anything that needs to be done at the end of the block.
			// We just kill our dummy storage item.
		}

		// A runtime code run after every block and have access to extended set of APIs.
		//
		// For instance you can generate extrinsics for the upcoming produced block.
		fn offchain_worker(_n: T::BlockNumber) {
			// We don't do anything here.
			// but we could dispatch extrinsic (transaction/unsigned/inherent) using
			// sp_io::submit_extrinsic
		}
	}
}

// The main implementation block for the pallet. Functions here fall into three broad
// categories:
// - Public interface. These are functions that are `pub` and generally fall into inspector
// functions that do not write to storage and operation functions that do.
// - Private functions. These are your usual private utilities unavailable to other pallets.
impl<T: Trait> Module<T> {
	// Add public immutables and private mutables.
}

#[cfg(test)]
mod tests {
	use super::*;
	use primitives::{ed25519, Blake2Hasher, H256, Pair};
	use runtime_io::with_externalities;
	use support::{assert_ok, impl_outer_origin};

	use runtime_primitives::{
		testing::{Digest, DigestItem, Header},
		traits::{BlakeTwo256, IdentityLookup},
		BuildStorage,
	};

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;
	impl system::Trait for Test {
		type Origin = Origin;
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type Digest = Digest;
		type AccountId = H256;
		type Header = Header;
		type Event = ();
		type Log = DigestItem;
		type Lookup = IdentityLookup<H256>;
	}

	impl Trait for Test {
		type Event = ();
		type PublicSigningKey = H256;
		type PublicBoxKey = H256;
	}

	type DID = Module<Test>;

	fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
		system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap()
			.0
			.into()
	}

	#[test]
	fn check_add_did() {
		with_externalities(&mut new_test_ext(), || {
			let pair = ed25519::Pair::from_seed(*b"Alice                           ");
			let signing_key = H256::from_low_u64_be(1);
			let box_key = H256::from_low_u64_be(2);
			let account_hash = H256::from(pair.public().0);
			assert_ok!(DID::add(
				Origin::signed(account_hash),
				signing_key,
				box_key,
				Some(b"http://kilt.org/submit".to_vec())
			));

			assert_eq!(<DIDs<Test>>::exists(account_hash), true);
			let did = {
				let opt = DID::dids(account_hash);
				assert!(opt.is_some());
				opt.unwrap()
			};
			assert_eq!(did.0, signing_key);
			assert_eq!(did.1, box_key);
			assert_eq!(did.2, Some(b"http://kilt.org/submit".to_vec()));

			assert_ok!(DID::remove(Origin::signed(account_hash)));
			assert_eq!(<DIDs<Test>>::exists(account_hash), false);
		});
	}
}
