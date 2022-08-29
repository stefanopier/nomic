use std::path::PathBuf;
extern crate self as nomic;

use bitcoincore_rpc_async::{Auth, Client as BtcClient};
use clap::Parser;
use nomic::bitcoin::{relayer::Relayer, signer::Signer};
use nomic::error::Result;
use orga::prelude::*;
use serde::{Deserialize, Serialize};

pub fn app_client() -> TendermintClient<nomic::app::App> {
    TendermintClient::new("http://localhost:26657").unwrap()
}

fn my_address() -> Address {
    let privkey = load_privkey().unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &privkey);
    Address::from_pubkey(pubkey.serialize())
}

#[derive(Parser, Debug)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = "The Nomic Developers <hello@nomic.io>"
)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    Start(StartCmd),
    #[cfg(debug_assertions)]
    StartDev(StartDevCmd),
    Send(SendCmd),
    SendNbtc(SendNbtcCmd),
    Balance(BalanceCmd),
    Delegations(DelegationsCmd),
    Validators(ValidatorsCmd),
    Delegate(DelegateCmd),
    Declare(DeclareCmd),
    Unbond(UnbondCmd),
    Redelegate(RedelegateCmd),
    Unjail(UnjailCmd),
    Edit(EditCmd),
    Claim(ClaimCmd),
    ClaimAirdrop(ClaimAirdropCmd),
    Relayer(RelayerCmd),
    Signer(SignerCmd),
    SetSignatoryKey(SetSignatoryKeyCmd),
    Deposit(DepositCmd),
    Withdraw(WithdrawCmd),
}

impl Command {
    pub async fn run(&self) -> Result<()> {
        use Command::*;
        match self {
            Start(cmd) => cmd.run().await,
            #[cfg(debug_assertions)]
            StartDev(cmd) => cmd.run().await,
            Send(cmd) => cmd.run().await,
            SendNbtc(cmd) => cmd.run().await,
            Balance(cmd) => cmd.run().await,
            Delegate(cmd) => cmd.run().await,
            Declare(cmd) => cmd.run().await,
            Delegations(cmd) => cmd.run().await,
            Validators(cmd) => cmd.run().await,
            Unbond(cmd) => cmd.run().await,
            Redelegate(cmd) => cmd.run().await,
            Unjail(cmd) => cmd.run().await,
            Edit(cmd) => cmd.run().await,
            Claim(cmd) => cmd.run().await,
            ClaimAirdrop(cmd) => cmd.run().await,
            Relayer(cmd) => cmd.run().await,
            Signer(cmd) => cmd.run().await,
            SetSignatoryKey(cmd) => cmd.run().await,
            Deposit(cmd) => cmd.run().await,
            Withdraw(cmd) => cmd.run().await,
        }
    }
}

#[derive(Parser, Debug)]
pub struct StartCmd {
    #[clap(long, short)]
    pub state_sync: bool,
}

impl StartCmd {
    async fn run(&self) -> Result<()> {
        unreachable!()
    }
}

#[cfg(debug_assertions)]
#[derive(Parser, Debug)]
pub struct StartDevCmd {}

#[cfg(debug_assertions)]
impl StartDevCmd {
    async fn run(&self) -> Result<()> {
        unreachable!()
    }
}

#[derive(Parser, Debug)]
pub struct SendCmd {
    to_addr: Address,
    amount: u64,
}

impl SendCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .accounts
            .transfer(self.to_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct SendNbtcCmd {
    to_addr: Address,
    amount: u64,
}

impl SendNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .bitcoin
                    .transfer(self.to_addr, self.amount.into())
                    .await
            })
            .noop()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct BalanceCmd {
    address: Option<Address>,
}

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        let address = self.address.unwrap_or_else(|| my_address());
        println!("address: {}", address);

        let balance = app_client().accounts.balance(address).await??;
        println!("{} NOM", balance);

        let balance = app_client().bitcoin.accounts.balance(address).await??;
        println!("{} NBTC", balance);

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegationsCmd;

impl DelegationsCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();
        let delegations = app_client().staking.delegations(address).await??;

        println!(
            "delegated to {} validator{}",
            delegations.len(),
            if delegations.len() == 1 { "" } else { "s" }
        );
        for (validator, delegation) in delegations {
            let staked = delegation.staked;
            let liquid: u64 = delegation
                .liquid
                .iter()
                .map(|(_, amount)| -> u64 { (*amount).into() })
                .sum();
            if staked == 0 && liquid == 0 {
                continue;
            }

            use nomic::app::Nom;
            use nomic::bitcoin::Nbtc;
            let liquid_nom = delegation
                .liquid
                .iter()
                .find(|(denom, _)| *denom == Nom::INDEX)
                .unwrap()
                .1;
            let liquid_nbtc = delegation
                .liquid
                .iter()
                .find(|(denom, _)| *denom == Nbtc::INDEX)
                .unwrap_or(&(0, 0.into()))
                .1;

            println!(
                "- {validator}: staked={staked} NOM, liquid={liquid_nom} NOM,{liquid_nbtc} NBTC",
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ValidatorsCmd;

impl ValidatorsCmd {
    async fn run(&self) -> Result<()> {
        let mut validators = app_client().staking.all_validators().await??;

        validators.sort_by(|a, b| b.amount_staked.cmp(&a.amount_staked));

        for validator in validators {
            let info: DeclareInfo =
                serde_json::from_slice(validator.info.bytes.as_slice()).unwrap();
            println!(
                "- {}\n\tVOTING POWER: {}\n\tMONIKER: {}\n\tDETAILS: {}",
                validator.address, validator.amount_staked, info.moniker, info.details
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegateCmd {
    validator_addr: Address,
    amount: u64,
}

impl DelegateCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
            })
            .staking
            .delegate_from_self(self.validator_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct DeclareCmd {
    consensus_key: String,
    amount: u64,
    commission_rate: Decimal,
    commission_max: Decimal,
    commission_max_change: Decimal,
    min_self_delegation: u64,
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeclareInfo {
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

impl DeclareCmd {
    async fn run(&self) -> Result<()> {
        use std::convert::TryInto;
        let consensus_key: [u8; 32] = base64::decode(&self.consensus_key)
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?
            .try_into()
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?;

        let info = DeclareInfo {
            moniker: self.moniker.clone(),
            website: self.website.clone(),
            identity: self.identity.clone(),
            details: self.details.clone(),
        };
        let info_json = serde_json::to_string(&info)
            .map_err(|_| orga::Error::App("invalid json".to_string()))?;
        let info_bytes = info_json.as_bytes().to_vec();

        let declaration = Declaration {
            consensus_key,
            amount: self.amount.into(),
            validator_info: info_bytes.into(),
            commission: Commission {
                rate: self.commission_rate,
                max: self.commission_max,
                max_change: self.commission_max_change,
            },
            min_self_delegation: self.min_self_delegation.into(),
        };

        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
            })
            .staking
            .declare_self(declaration)
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct EditCmd {
    commission_rate: Decimal,
    min_self_delegation: u64,
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

impl EditCmd {
    async fn run(&self) -> Result<()> {
        let info = DeclareInfo {
            moniker: self.moniker.clone(),
            website: self.website.clone(),
            identity: self.identity.clone(),
            details: self.details.clone(),
        };
        let info_json = serde_json::to_string(&info)
            .map_err(|_| orga::Error::App("invalid json".to_string()))?;
        let info_bytes = info_json.as_bytes().to_vec();

        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .edit_validator_self(
                self.commission_rate,
                self.min_self_delegation.into(),
                info_bytes.into(),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct UnbondCmd {
    validator_addr: Address,
    amount: u64,
}

impl UnbondCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .unbond_self(self.validator_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct RedelegateCmd {
    src_validator_addr: Address,
    dest_validator_addr: Address,
    amount: u64,
}

impl RedelegateCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .redelegate_self(
                self.src_validator_addr,
                self.dest_validator_addr,
                self.amount.into(),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct UnjailCmd {}

impl UnjailCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .unjail()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimCmd;

impl ClaimCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.staking.claim_all().await)
            .deposit_rewards()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimAirdropCmd;

impl ClaimAirdropCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.atom_airdrop.claim().await)
            .accounts
            .give_from_funding_all()
            .await?)
    }
}
#[derive(Parser, Debug)]
pub struct RelayerCmd {
    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,

    #[clap(short = 'u', long)]
    rpc_user: Option<String>,

    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,

    #[clap(long)]
    path: Option<String>,
}

impl RelayerCmd {
    async fn btc_client(&self) -> Result<BtcClient> {
        let rpc_url = format!("http://localhost:{}", self.rpc_port);
        let auth = match (self.rpc_user.clone(), self.rpc_pass.clone()) {
            (Some(user), Some(pass)) => Auth::UserPass(user, pass),
            _ => Auth::None,
        };

        let btc_client = BtcClient::new(rpc_url, auth)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;

        Ok(btc_client)
    }

    async fn run(&self) -> Result<()> {
        let create_relayer = async || {
            let btc_client = self.btc_client().await.unwrap();

            Relayer::new(btc_client, app_client()).await
        };

        let mut relayer = create_relayer().await;
        let headers = relayer.start_header_relay();

        let relayer_dir_path = self
            .path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Node::home(nomic::app::CHAIN_ID).join("relayer"));
        if !relayer_dir_path.exists() {
            std::fs::create_dir(&relayer_dir_path)?;
        }
        let mut relayer = create_relayer().await;
        let deposits = relayer.start_deposit_relay(relayer_dir_path);

        let mut relayer = create_relayer().await;
        let checkpoints = relayer.start_checkpoint_relay();

        futures::try_join!(headers, deposits, checkpoints).unwrap();

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SignerCmd {
    #[clap(short, long)]
    path: Option<String>,
}

impl SignerCmd {
    async fn run(&self) -> Result<()> {
        let signer_dir_path = self
            .path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Node::home(nomic::app::CHAIN_ID).join("signer"));
        if !signer_dir_path.exists() {
            std::fs::create_dir(&signer_dir_path)?;
        }
        let key_path = signer_dir_path.join("xpriv");

        let signer = Signer::load_or_generate(app_client(), key_path)?;
        signer.start().await?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SetSignatoryKeyCmd {
    xpub: bitcoin::util::bip32::ExtendedPubKey,
}

impl SetSignatoryKeyCmd {
    async fn run(&self) -> Result<()> {
        app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .bitcoin
            .set_signatory_key(self.xpub.into())
            .await?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DepositCmd {
    address: Option<Address>,
}

impl DepositCmd {
    async fn run(&self) -> Result<()> {
        let dest_addr = self.address.unwrap_or_else(|| my_address());

        let sigset = app_client().bitcoin.checkpoints.active_sigset().await??;
        let script = sigset.output_script(dest_addr)?;
        // TODO: get network from somewhere
        let btc_addr = bitcoin::Address::from_script(&script, bitcoin::Network::Testnet).unwrap();

        let client = reqwest::Client::new();
        client
            .post(format!(
                "http://167.99.228.240:9000?dest_addr={}&sigset_index={}&deposit_addr={}",
                dest_addr,
                sigset.index(),
                btc_addr,
            ))
            .send()
            .await
            .map_err(|err| nomic::error::Error::Orga(orga::Error::App(err.to_string())))?;

        println!("Deposit address: {}", btc_addr);
        println!("Expiration: {}", "TODO");
        // TODO: show real expiration

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct WithdrawCmd {
    dest: bitcoin::Address,
    amount: u64,
}

impl WithdrawCmd {
    async fn run(&self) -> Result<()> {
        use nomic::bitcoin::adapter::Adapter;

        let script = self.dest.script_pubkey();

        app_client()
            .pay_from(async move |client| {
                client
                    .bitcoin
                    .withdraw(Adapter::new(script), self.amount.into())
                    .await
            })
            .noop()
            .await?;

        Ok(())
    }
}
