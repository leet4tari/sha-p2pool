// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashMap, env, fs, sync::Arc};

use libp2p::identity::Keypair;
use log::info;
use tari_common::{configuration::Network, initialize_logging};
use tari_core::{
    consensus::ConsensusManager,
    proof_of_work::{randomx_factory::RandomXFactory, PowAlgorithm},
};
use tari_shutdown::ShutdownSignal;
use tari_utilities::hex::Hex;
use tokio::sync::RwLock;

use crate::{
    cli::args::{Cli, StartArgs},
    server::{
        self as main_server,
        http::stats_collector::{StatsBroadcastClient, StatsCollector},
        server::Server,
    },
    sharechain::{in_memory::InMemoryShareChain, BlockValidationParams},
};

#[allow(clippy::too_many_lines)]
pub async fn server(
    cli: Arc<Cli>,
    args: &StartArgs,
    shutdown_signal: ShutdownSignal,
    enable_logging: bool,
) -> anyhow::Result<Server<InMemoryShareChain>> {
    if enable_logging {
        let _unused = fs::remove_file(cli.base_dir().join("configs/logs.yml"));
        // logger setup
        if let Err(e) = initialize_logging(
            &cli.base_dir().join("configs/logs.yml"),
            &cli.base_dir(),
            include_str!("../../../log4rs_sample.yml"),
        ) {
            eprintln!("{}", e);
            return Err(e.into());
        }
    }

    let mut config_builder = main_server::Config::builder();
    if let Some(grpc_port) = args.grpc_port {
        config_builder.with_grpc_port(grpc_port);
    }
    if let Some(p2p_port) = args.p2p_port {
        config_builder.with_p2p_port(p2p_port);
    }

    if let Some(block_time) = args.block_time {
        config_builder.with_block_time(block_time);
    }

    if let Some(share_window) = args.share_window {
        config_builder.with_share_window(share_window);
    }

    config_builder.with_squad_prefix(args.squad_prefix.clone());
    config_builder.with_num_squads(args.num_squads);

    // set default tari network specific seed peer address
    let mut seed_peers = vec![];
    let network = Network::get_current_or_user_setting_or_default();
    if network != Network::LocalNet && !args.no_default_seed_peers {
        let default_seed_peer = format!("/dnsaddr/{}.sha-p2pool.tari.com", network.as_key_str());
        seed_peers.push(default_seed_peer);
    }
    if let Some(cli_seed_peers) = args.seed_peers.clone() {
        seed_peers.extend(cli_seed_peers.iter().cloned());
    }
    config_builder.with_seed_peers(seed_peers);

    config_builder.with_stable_peer(args.stable_peer);
    config_builder.with_private_key_folder(args.private_key_folder.clone());
    if let Some(max_connections) = args.max_connections {
        config_builder.with_max_outgoing_connections(max_connections);
        config_builder.with_max_incoming_connections(max_connections);
    }
    config_builder.with_randomx_enabled(!args.randomx_disabled);
    config_builder.with_sha3x_enabled(!args.sha3x_disabled);

    // try to extract env var based private key
    if let Ok(identity_cbor) = env::var("SHA_P2POOL_IDENTITY") {
        let identity_raw = hex::decode(identity_cbor.as_bytes())?;
        let private_key = Keypair::from_protobuf_encoding(identity_raw.as_slice())?;
        config_builder.with_private_key(Some(private_key));
    }

    // external address
    if let Some(external_addr) = &args.external_address {
        config_builder.with_external_address(external_addr.clone());
    }
    if let Ok(external_ip) = env::var("SHA_P2POOL_ADDRESS") {
        config_builder.with_external_address(external_ip);
    }

    config_builder.with_is_seed_peer(args.is_seed_peer);
    config_builder.with_mdns_enabled(!args.mdns_disabled);
    config_builder.with_relay_disabled(args.relay_server_disabled);
    config_builder.with_relay_max_circuits(args.relay_server_max_circuits);
    config_builder.with_relay_max_circuits_per_peer(args.relay_server_max_circuits_per_peer);
    config_builder.with_http_server_enabled(!args.http_server_disabled);
    config_builder.with_user_agent(
        args.user_agent
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "tari-p2pool".to_string()),
    );
    config_builder.with_peer_publish_interval(args.peer_publish_interval);
    config_builder.with_debug_print_chain(args.debug_print_chain);
    if let Some(stats_server_port) = args.stats_server_port {
        config_builder.with_stats_server_port(stats_server_port);
    }
    config_builder.with_base_node_address(args.base_node_address.clone());

    config_builder.with_block_cache_file(env::current_dir()?.join("block_cache"));
    let config = config_builder.build();
    let randomx_factory = RandomXFactory::new(1);
    let consensus_manager = ConsensusManager::builder(Network::get_current_or_user_setting_or_default()).build()?;
    let genesis_block_hash = *consensus_manager.get_genesis_block().hash();

    info!(target: "p2pool::server", "Consensus manager initialized with network: {}, and genesis hash {}", Network::get_current_or_user_setting_or_default(),
genesis_block_hash.to_hex());
    let block_validation_params = Arc::new(BlockValidationParams::new(
        randomx_factory,
        consensus_manager.clone(),
        genesis_block_hash,
    ));
    let coinbase_extras_sha3x = Arc::new(RwLock::new(HashMap::<String, Vec<u8>>::new()));

    let (stats_tx, stats_rx) = tokio::sync::broadcast::channel(1000);
    let stats_broadcast_client = StatsBroadcastClient::new(stats_tx);
    let stats_collector = StatsCollector::new(shutdown_signal.clone(), stats_rx);

    let share_chain_sha3x = InMemoryShareChain::new(
        config.clone(),
        PowAlgorithm::Sha3x,
        None,
        consensus_manager.clone(),
        coinbase_extras_sha3x.clone(),
        stats_broadcast_client.clone(),
    )?;
    let coinbase_extras_random_x = Arc::new(RwLock::new(HashMap::<String, Vec<u8>>::new()));
    let share_chain_random_x = InMemoryShareChain::new(
        config.clone(),
        PowAlgorithm::RandomX,
        Some(block_validation_params.clone()),
        consensus_manager,
        coinbase_extras_random_x.clone(),
        stats_broadcast_client.clone(),
    )?;

    Server::new(
        config,
        share_chain_sha3x,
        share_chain_random_x,
        stats_collector,
        stats_broadcast_client,
        shutdown_signal,
    )
    .await
}
