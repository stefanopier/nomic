use clap::Parser;
use csv::Reader;
use nomic::airdrop::Part;
use nomic::app::App;
use orga::store::BackingStore;
use orga::merk::MerkStore;
use orga::coins::Address;
use orga::state::State;
use orga::store::Shared;
use orga::store::Store;
use std::str::FromStr;

#[derive(Parser, Debug)]
pub struct Opts {
    #[clap(short, long)]
    merk_path: String,
    #[clap(short, long)]
    airdrop_csv_path: String,
}

fn is_claimed(airdrop_part: &Part) -> bool {
    airdrop_part.claimed > 0 || airdrop_part.claimable > 0
}

pub fn main() {
    let opts = Opts::parse();

    let mut reader = Reader::from_path(&opts.airdrop_csv_path).unwrap();
    let mut headers = reader.headers().unwrap().clone();
    headers.extend([
        "btc_deposit_claimed",
        "btc_withdraw_claimed",
        "ibc_transfer_claimed",
    ]);

    let merk = MerkStore::new(&opts.merk_path);
    let root_bytes = merk.merk().get(&[]).unwrap().unwrap();
    let app = orga::plugins::ABCIPlugin::<App>::load(
        Store::new(BackingStore::Merk(Shared::new(merk))),
        &mut root_bytes.as_slice(),
    )
    .unwrap();

    for result in reader.records() {
        let mut record = result.unwrap();
        let addr = record.get(0).unwrap();
        if addr.len() != 44 {
            continue;
        }
        let airdrop_account = app
            .inner
            .inner
            .borrow()
            .inner
            .inner
            .inner
            .inner
            .inner
            .airdrop
            .get(Address::from_str(addr).unwrap())
            .unwrap()
            .unwrap();

        let btc_deposit = is_claimed(&airdrop_account.btc_deposit);
        let btc_withdraw = is_claimed(&airdrop_account.btc_withdraw);
        let ibc_transfer = is_claimed(&airdrop_account.ibc_transfer);

        if !btc_deposit && !btc_withdraw && !ibc_transfer {
            continue;
        }

        println!(
            "{},{},{},{}",
            addr,
            btc_deposit,
            btc_withdraw,
            ibc_transfer
        );
    }
}
