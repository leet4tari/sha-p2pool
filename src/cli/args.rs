// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use tari_shutdown::ShutdownSignal;

use crate::cli::{
    commands,
    util::{cli_styles, validate_squad},
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Parser, Debug)]
pub(crate) struct StartArgs {
    /// (Optional) base dir.
    #[arg(short, long, value_name = "base-dir")]
    base_dir: Option<PathBuf>,

    /// (Optional) gRPC port to use.
    #[arg(short, long, value_name = "grpc-port")]
    pub grpc_port: Option<u16>,

    /// (Optional) p2p port to use. It is used to connect p2pool nodes.
    #[arg(short, long, value_name = "p2p-port")]
    pub p2p_port: Option<u16>,

    /// (Optional) stats server port to use.
    #[arg(long, value_name = "stats-server-port")]
    pub stats_server_port: Option<u16>,

    /// (Optional) External address to listen on.
    #[arg(long, value_name = "external-address")]
    pub external_address: Option<String>,

    /// (Optional) Address of the Tari base node.
    #[arg(long, value_name = "base-node-address", default_value = "http://127.0.0.1:18182")]
    pub base_node_address: String,

    /// (Optional) seed peers.
    /// Any amount of seed peers can be added to join a p2pool network.
    ///
    /// Please note that these addresses must be in libp2p multi address format and must contain peer ID
    /// or use a dnsaddr multi address!
    ///
    /// By default a Tari provided seed peer is added.
    ///
    /// e.g.:
    /// /ip4/127.0.0.1/tcp/52313/p2p/12D3KooWCUNCvi7PBPymgsHx39JWErYdSoT3EFPrn3xoVff4CHFu
    /// /dnsaddr/esmeralda.sha-p2pool.tari.com
    #[arg(short, long, value_name = "seed-peers")]
    pub seed_peers: Option<Vec<String>>,

    /// If set, Tari provided seed peers will NOT be automatically added to seed peers list.
    #[arg(long, value_name = "no-default-seed-peers", default_value_t = false)]
    pub no_default_seed_peers: bool,

    /// Starts the node as a stable peer.
    ///
    /// Identity of the peer will be saved locally (to --private-key-location)
    /// and ID of the Peer remains the same.
    #[arg(long, value_name = "stable-peer", default_value_t = false)]
    pub stable_peer: bool,

    /// Squad to enter (a team of miners).
    /// A squad can have any name.
    #[arg(
        long, alias = "squad", value_name = "squad", default_value = "default", value_parser = validate_squad
    )]
    pub squad_prefix: String,

    #[arg(long, value_name = "num-squads", default_value = "1")]
    pub num_squads: usize,

    /// Private key folder.
    ///
    /// Needs --stable-peer to be set.
    #[arg(
        long,
        value_name = "private-key-folder",
        requires = "stable_peer",
        default_value = "."
    )]
    pub private_key_folder: PathBuf,

    #[arg(long, default_value_t = false)]
    pub is_seed_peer: bool,

    /// mDNS disabled
    ///
    /// If set, mDNS local peer discovery is disabled.
    #[arg(long, value_name = "mdns-disabled", default_value_t = false)]
    pub mdns_disabled: bool,

    /// Relay Server  - Default is set to false. If the node
    /// has an external address, it will relay
    #[arg(long, value_name = "relay-server-disabled", default_value_t = false)]
    pub relay_server_disabled: bool,

    /// Relay Server Max Circuits
    #[arg(long, value_name = "relay-server-max-circuits")]
    pub relay_server_max_circuits: Option<usize>,

    /// Relay Server Max Circuits per peer
    #[arg(long, value_name = "relay-server-max-circuits-per-peer")]
    pub relay_server_max_circuits_per_peer: Option<usize>,

    /// HTTP server disabled
    ///
    /// If set, local HTTP server (stats, health-check, status etc...) is disabled.
    #[arg(long, value_name = "http-server-disabled", default_value_t = false)]
    pub http_server_disabled: bool,

    #[arg(long, value_name = "user-agent")]
    pub user_agent: Option<String>,

    #[arg(long)]
    pub peer_publish_interval: Option<u64>,

    #[arg(long)]
    pub debug_print_chain: bool,

    #[arg(long)]
    pub max_connections: Option<u32>,

    #[arg(long, default_value_t = false)]
    pub randomx_disabled: bool,
    #[arg(long, default_value_t = false)]
    pub sha3x_disabled: bool,

    #[arg(long, value_name = "bt")]
    pub block_time: Option<u64>,

    #[arg(long, value_name = "sw")]
    pub share_window: Option<u64>,
}

#[derive(Clone, Parser, Debug)]
pub struct ListSquadArgs {
    /// List squad command timeout in seconds.
    ///
    /// The list-squads commands tries to look for all the currently available squads
    /// for this amount of time maximum.
    #[arg(long, value_name = "timeout", default_value_t = 15)]
    pub timeout: u64,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Starts sha-p2pool node.
    Start {
        #[clap(flatten)]
        args: StartArgs,
    },

    /// Generating new identity.
    GenerateIdentity,

    /// Listing all squads that are present on the network.
    ListSquads {
        #[clap(flatten)]
        args: StartArgs,

        #[clap(flatten)]
        list_squad_args: ListSquadArgs,
    },
}

#[derive(Clone, Parser)]
#[command(version)]
#[command(styles = cli_styles())]
#[command(about = "⛏ Decentralized mining pool for Tari network ⛏", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn base_dir(&self) -> PathBuf {
        match &self.command {
            Commands::Start { args } => args
                .base_dir
                .clone()
                .unwrap_or_else(|| dirs::home_dir().unwrap().join(".tari/p2pool")),
            Commands::GenerateIdentity => dirs::home_dir().unwrap().join(".tari/p2pool"),
            Commands::ListSquads {
                args,
                list_squad_args: _list_squad_args,
            } => args
                .base_dir
                .clone()
                .unwrap_or_else(|| dirs::home_dir().unwrap().join(".tari/p2pool")),
        }
    }

    /// Handles CLI command.
    /// [`Cli::parse`] must be called (to have all the args and params set properly)
    /// before calling this method.
    pub async fn handle_command(&self, cli_shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let cli_ref = Arc::new(self.clone());

        match &self.command {
            Commands::Start { args } => {
                commands::handle_start(cli_ref.clone(), args, cli_shutdown.clone()).await?;
            },
            Commands::GenerateIdentity => {
                commands::handle_generate_identity().await?;
            },
            Commands::ListSquads { args, list_squad_args } => {
                commands::handle_list_squads(cli_ref.clone(), args, list_squad_args, cli_shutdown.clone()).await?;
            },
        }

        Ok(())
    }
}
