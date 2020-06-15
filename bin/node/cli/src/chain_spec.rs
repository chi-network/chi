// This file is part of Substrate.

// Copyright (C) 2018-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Substrate chain configurations.

use sc_chain_spec::ChainSpecExtension;
use sp_core::{Pair, Public, crypto::UncheckedInto, sr25519};
use serde::{Serialize, Deserialize};
use node_runtime::{
	AuthorityDiscoveryConfig, BabeConfig, BalancesConfig, ContractsConfig, CouncilConfig,
	DemocracyConfig,GrandpaConfig, ImOnlineConfig, SessionConfig, SessionKeys, StakerStatus,
	StakingConfig, ElectionsConfig, IndicesConfig, SocietyConfig, SudoConfig, SystemConfig,
	TechnicalCommitteeConfig, WASM_BINARY,
};
use node_runtime::Block;
use node_runtime::constants::currency::*;
use sc_service::ChainType;
use hex_literal::hex;
use sc_telemetry::TelemetryEndpoints;
use grandpa_primitives::{AuthorityId as GrandpaId};
use sp_consensus_babe::{AuthorityId as BabeId};
use pallet_im_online::sr25519::{AuthorityId as ImOnlineId};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_runtime::{Perbill, traits::{Verify, IdentifyAccount}};

pub use node_primitives::{AccountId, Balance, Signature};
pub use node_runtime::GenesisConfig;

type AccountPublic = <Signature as Verify>::Signer;

const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Node `ChainSpec` extensions.
///
/// Additional parameters for some Substrate core modules,
/// customizable from the chain spec.
#[derive(Default, Clone, Serialize, Deserialize, ChainSpecExtension)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
	/// Block numbers with known hashes.
	pub fork_blocks: sc_client_api::ForkBlocks<Block>,
	/// Known bad block hashes.
	pub bad_blocks: sc_client_api::BadBlocks<Block>,
}

/// Specialized `ChainSpec`.
pub type ChainSpec = sc_service::GenericChainSpec<
	GenesisConfig,
	Extensions,
>;
/// Flaming Fir testnet generator
pub fn chi_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/chi.json")[..])
}

fn session_keys(
	grandpa: GrandpaId,
	babe: BabeId,
	im_online: ImOnlineId,
	authority_discovery: AuthorityDiscoveryId,
) -> SessionKeys {
	SessionKeys { grandpa, babe, im_online, authority_discovery }
}

fn staging_testnet_config_genesis() -> GenesisConfig {
	// stash, controller, session-key
	// generated with secret:
	// for i in 1 2 3 4 ; do for j in stash controller; do subkey inspect "$secret"/fir/$j/$i; done; done
	// and
	// for i in 1 2 3 4 ; do for j in session; do subkey --ed25519 inspect "$secret"//fir//$j//$i; done; done

	let initial_authorities: Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)> = vec![(
		// 5GnE1R1wsDXd6EEsLqnpW24vByBY7Y7x1ARar7BxNP2Gut2r
		hex!["d09b7df4c169397a5c152be410ca3ac1a4b1b229cfb68f14191adb32b0d0682d"].into(),
		// 5FTRPuWFep2SD7u2Zfm6YdX3fiMEwXcKscvoeFFfZVnEhf53
		hex!["9607ee393c9e922ea8969560069c1005476f752f3803cd7b0be377e8aac4dc20"].into(),
		// 5CR4rYAfuTyYjDmLvvRivs5CX2nrJTHoCLVbujkAz3aRH9rk
		hex!["0f8797c267c56aa966d05b7f0fd7eb457d2897ffb34045a391cb6143d20c82af"].unchecked_into(),
		// 5CaCsAfbrYbd9a6PK98VEbUdBCunnLbVXPNK8172qJLeG6s3
		hex!["167fc4b42459ff0bc857236b9811e6f53469a64f60cb202fee5a0e76f209c040"].unchecked_into(),
		// 5DtpaL5v19x3ywZ77zaoyKrHyd8Wjb2eNdxs9Vk8x3HDuQ1q
		hex!["50eea0efd2ca33f4f95ef5b0069950471a1f203906a671785be7638dc137eb05"].unchecked_into(),
		// 5Dw7N13SfaqAcEHPeuVhtWMcSox9j48uBnN6gsNDEeuQfapt
		hex!["52ada18bb3504cc371095cdf897427a164ef5f4237bd778c46685bb4b931f569"].unchecked_into(),
	),(
		// 5Ea6ZhWypDZee74f7GSmUV6SHGV2T13C4cTF5e1KBQy8QHzw
		hex!["6ee3060d21fb08bd859c09a78fa7b128c5d63a0143140b8b228277e5c1f33e02"].into(),
		// 5Fpk7yPSH7Pj3YyFBmoHZJsJaL2uGr6ZLwgw8jN2NTGjEeQB
		hex!["a64b1e77145adc27ac2b45b564a27f27d866091d8bfe0d1381243b32be364576"].into(),
		// 5CLmi5zk7ddKrRHiFBRp2ZiH4TSHc9BUWuVhgoK6c6NqTcqR
		hex!["0c40e4c1fe5a066b51568518ead6ada5214f1633ec26ab2ff66432016a6793dd"].unchecked_into(),
		// 5EnprychvDmw97XnUME62uyXX8fm3dnxZ6GfTPJ13McBDWPP
		hex!["78985b1ac5f9808bf4db78695cd1482244bb67455dc5e5a802142a80d9d0a423"].unchecked_into(),
		// 5EypVQthNceGVdp6yUdq9pfkZtnZGDyzhxnyg9x1szrpt87K
		hex!["80facdc248d9221cceedc3f0ea24a5fc850fd3fa8136c06ebff67b3e2e38815c"].unchecked_into(),
		// 5GBaVPU6q4afMzQnhZNiuqC8Eyivh71NMgVjgsngQvEXvGMm
		hex!["b62eda3886d57f759b7e821bca04e0ae4e473b53e47ab21fed26c8604eefec27"].unchecked_into(),
	),(
		// 5DhC85UYCTLe4bxLi5kFCXireeJXT4f3JopTwrb437QqJW9q
		hex!["4810380081de9aadc9f966b44a4263055359a501ca9808159af658788d395c01"].into(),
		// 5FKwL7B2bWZzkQPQZhQyi95ykdHBQMz8HgPqpGneGSQvscT8
		hex!["9052bc6069268d6c2a7a5cf0f2421f743a42ed5cda0715e0ef1868c8487ffc11"].into(),
		// 5EtAWdHSSVYXepurUC3AeWUthohiNn1Bzt2fjx99in45YpJc
		hex!["7caaba4e91bfdb2b8ea942d0297875797126d5de326eda8fb1631729200ace7d"].unchecked_into(),
		// 5DZUpYm2DiebekeN6AfoJzbYJQJ1ZeGAt3mv6rn7hL2PVTxh
		hex!["422e7718359b536b4f7b30b017af7abccc10e74036893566c7963a316e1a982a"].unchecked_into(),
		// 5HEVqwE2NuuM2a3gZr3X6t1kJQLfYGUz276Y764KQLVU7eC4
		hex!["e4a52ee3c2d5179374400ce05b8085e489e1cc3f0344233efb8e7722acf08f3c"].unchecked_into(),
		// 5HeNuZH6Qthuha5rP95i8dkjFnhydyA9YnkqKuWR5A7YgNUr
		hex!["f6dbb80dfee06a84cd8ce798bf39661c40ab2dcc3071097b1c3f626eacf91f0c"].unchecked_into(),
	),(
		// 5DPrAeoFAJbieXjrwGNLm7apBoxSBz2KATPUVpFj9BFLz6gj
		hex!["3ad5decc6b976a0bd74c4aafa865a61f7bffca79e4cf76aeb42fc30101ce6156"].into(),
		// 5CoAgfyBwcRbYodrq1g6ip65yFXUSUL6LzbWqP8qqMBmWn46
		hex!["20629dee4ba8f8fcadf9f8320f9a66b0964a60323e7824c63f8c7acaf336f971"].into(),
		// 5HPHpBfgWpsfk9kFnQoPvMJR1JdL4ooJwEZSvaTrSU4jBQnw
		hex!["eb59e502cfa41416f4b5e97aa10971d2ce6ff275a00dfb4865edd6bf14020b0a"].unchecked_into(),
		// 5FHWXwNgzcxDUufkFuS6J3dXd2X5cLdEJyeqtv6mDDyRCJmu
		hex!["8e78c632592f008f323a7948c5bffcb83a18a004291fc0ada60885f16c031d08"].unchecked_into(),
		// 5GHSJdcSviysbkjtfQsxqVuAXfAkEmvtapuQHxt5AaM6VYK4
		hex!["baa6c529ba18268cba6498c608df6b896b0a721c360926e93831bbbe5c65972f"].unchecked_into(),
		// 5Ec4ApxKfrBJUHMxWBFhLUznwbCvS8CBLcty7rz6wqGm9EnP
		hex!["7061745202c483fabba8f9dd5dc192233d3321c77324051c6f69f50ba25df73b"].unchecked_into(),
	)];

	// generated with secret: subkey inspect "$secret"/fir
	let root_key: AccountId = hex![
		// 5CAwrCGi5K4Jmy7RA4FmaqSYPqueeBRtgzmFr9z9jk43ZQoD
		"04c292b93d7784770a3c27e1d675a9e448218fee72ac1ace0160fe3bd2067772"
	].into();

	let endowed_accounts: Vec<AccountId> = vec![root_key.clone()];

	testnet_genesis(
		initial_authorities,
		root_key,
		Some(endowed_accounts),
		false,
	)
}

/// Staging testnet config.
pub fn staging_testnet_config() -> ChainSpec {
	let boot_nodes = vec![];
	ChainSpec::from_genesis(
		"Staging Testnet",
		"staging_testnet",
		ChainType::Live,
		staging_testnet_config_genesis,
		boot_nodes,
		Some(TelemetryEndpoints::new(vec![(STAGING_TELEMETRY_URL.to_string(), 0)])
			.expect("Staging telemetry url is valid; qed")),
		None,
		None,
		Default::default(),
	)
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate stash, controller and session key from seed
pub fn authority_keys_from_seed(seed: &str) -> (
	AccountId,
	AccountId,
	GrandpaId,
	BabeId,
	ImOnlineId,
	AuthorityDiscoveryId,
) {
	(
		get_account_id_from_seed::<sr25519::Public>(&format!("{}//stash", seed)),
		get_account_id_from_seed::<sr25519::Public>(seed),
		get_from_seed::<GrandpaId>(seed),
		get_from_seed::<BabeId>(seed),
		get_from_seed::<ImOnlineId>(seed),
		get_from_seed::<AuthorityDiscoveryId>(seed),
	)
}

/// Helper function to create GenesisConfig for testing
pub fn testnet_genesis(
	initial_authorities: Vec<(
		AccountId,
		AccountId,
		GrandpaId,
		BabeId,
		ImOnlineId,
		AuthorityDiscoveryId,
	)>,
	root_key: AccountId,
	endowed_accounts: Option<Vec<AccountId>>,
	enable_println: bool,
) -> GenesisConfig {
	let endowed_accounts: Vec<AccountId> = endowed_accounts.unwrap_or_else(|| {
		vec![
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			get_account_id_from_seed::<sr25519::Public>("Bob"),
			get_account_id_from_seed::<sr25519::Public>("Charlie"),
			get_account_id_from_seed::<sr25519::Public>("Dave"),
			get_account_id_from_seed::<sr25519::Public>("Eve"),
			get_account_id_from_seed::<sr25519::Public>("Ferdie"),
			get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
			get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
			get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
			get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
			get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
			get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
		]
	});
	let num_endowed_accounts = endowed_accounts.len();

	const ENDOWMENT: Balance = 7_333_333 * CHI;
	const STASH: Balance = 111_111 * CHI;

	GenesisConfig {
		frame_system: Some(SystemConfig {
			code: WASM_BINARY.to_vec(),
			changes_trie_config: Default::default(),
		}),
		pallet_balances: Some(BalancesConfig {
			balances: endowed_accounts.iter().cloned()
				.map(|k| (k, ENDOWMENT))
				.chain(initial_authorities.iter().map(|x| (x.0.clone(), STASH)))
				.collect(),
		}),
		pallet_indices: Some(IndicesConfig {
			indices: vec![],
		}),
		pallet_session: Some(SessionConfig {
			keys: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.0.clone(), session_keys(
					x.2.clone(),
					x.3.clone(),
					x.4.clone(),
					x.5.clone(),
				))
			}).collect::<Vec<_>>(),
		}),
		pallet_staking: Some(StakingConfig {
			validator_count: initial_authorities.len() as u32 * 2,
			minimum_validator_count: initial_authorities.len() as u32,
			stakers: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator)
			}).collect(),
			invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect(),
			slash_reward_fraction: Perbill::from_percent(10),
			.. Default::default()
		}),
		pallet_democracy: Some(DemocracyConfig::default()),
		pallet_elections_phragmen: Some(ElectionsConfig {
			members: endowed_accounts.iter()
						.take((num_endowed_accounts + 1) / 2)
						.cloned()
						.map(|member| (member, STASH))
						.collect(),
		}),
		pallet_collective_Instance1: Some(CouncilConfig::default()),
		pallet_collective_Instance2: Some(TechnicalCommitteeConfig {
			members: endowed_accounts.iter()
						.take((num_endowed_accounts + 1) / 2)
						.cloned()
						.collect(),
			phantom: Default::default(),
		}),
		pallet_contracts: Some(ContractsConfig {
			current_schedule: pallet_contracts::Schedule {
				enable_println, // this should only be enabled on development chains
				..Default::default()
			},
		}),
		pallet_sudo: Some(SudoConfig {
			key: root_key,
		}),
		pallet_babe: Some(BabeConfig {
			authorities: vec![],
		}),
		pallet_im_online: Some(ImOnlineConfig {
			keys: vec![],
		}),
		pallet_authority_discovery: Some(AuthorityDiscoveryConfig {
			keys: vec![],
		}),
		pallet_grandpa: Some(GrandpaConfig {
			authorities: vec![],
		}),
		pallet_membership_Instance1: Some(Default::default()),
		pallet_treasury: Some(Default::default()),
		pallet_society: Some(SocietyConfig {
			members: endowed_accounts.iter()
						.take((num_endowed_accounts + 1) / 2)
						.cloned()
						.collect(),
			pot: 0,
			max_members: 777,
		}),
		pallet_vesting: Some(Default::default()),
	}
}

fn development_config_genesis() -> GenesisConfig {
	testnet_genesis(
		vec![
			authority_keys_from_seed("Alice"),
		],
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		None,
		true,
	)
}

/// Development config (single validator Alice)
pub fn development_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Development",
		"dev",
		ChainType::Development,
		development_config_genesis,
		vec![],
		None,
		None,
		None,
		Default::default(),
	)
}

fn local_testnet_genesis() -> GenesisConfig {
	testnet_genesis(
		vec![
			authority_keys_from_seed("Alice"),
			authority_keys_from_seed("Bob"),
		],
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		None,
		false,
	)
}

/// Local testnet config (multivalidator Alice + Bob)
pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Local Testnet",
		"local_testnet",
		ChainType::Local,
		local_testnet_genesis,
		vec![],
		None,
		None,
		None,
		Default::default(),
	)
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use crate::service::{new_full, new_light};
	use sc_service_test;
	use sp_runtime::BuildStorage;

	fn local_testnet_genesis_instant_single() -> GenesisConfig {
		testnet_genesis(
			vec![
				authority_keys_from_seed("Alice"),
			],
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			None,
			false,
		)
	}

	/// Local testnet config (single validator - Alice)
	pub fn integration_test_config_with_single_authority() -> ChainSpec {
		ChainSpec::from_genesis(
			"Integration Test",
			"test",
			ChainType::Development,
			local_testnet_genesis_instant_single,
			vec![],
			None,
			None,
			None,
			Default::default(),
		)
	}

	/// Local testnet config (multivalidator Alice + Bob)
	pub fn integration_test_config_with_two_authorities() -> ChainSpec {
		ChainSpec::from_genesis(
			"Integration Test",
			"test",
			ChainType::Development,
			local_testnet_genesis,
			vec![],
			None,
			None,
			None,
			Default::default(),
		)
	}

	#[test]
	#[ignore]
	fn test_connectivity() {
		sc_service_test::connectivity(
			integration_test_config_with_two_authorities(),
			|config| new_full(config),
			|config| new_light(config),
		);
	}

	#[test]
	fn test_create_development_chain_spec() {
		development_config().build_storage().unwrap();
	}

	#[test]
	fn test_create_local_testnet_chain_spec() {
		local_testnet_config().build_storage().unwrap();
	}

	#[test]
	fn test_staging_test_net_chain_spec() {
		staging_testnet_config().build_storage().unwrap();
	}
}
