pub use bitcoin;
pub use bitcoincore_rpc;

use std::io::{Read, Write};

use bitcoin::BlockHeader;
use orga::{Result, Encode, Decode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EnrichedHeader {
    pub height: u32,
    pub header: BlockHeader,
}

pub struct Script(pub bitcoin::Script);

impl From<bitcoin::Script> for Script {
    fn from(script: bitcoin::Script) -> Self {
        Script(script)
    }
}

impl From<Script> for bitcoin::Script {
    fn from(script: Script) -> Self {
        script.0
    }
}

impl Encode for Script {
    fn encode_into<W: Write>(&self, dest: &mut W) -> Result<()> {
        dest.write_all(self.0.as_bytes())?;
        Ok(())
    }

    fn encoding_length(&self) -> Result<usize> {
        Ok(self.0.len())
    }
}

impl Decode for Script {
    fn decode<R: Read>(input: R) -> Result<Self> {
        let bytes: Vec<u8> = Decode::decode(input)?;
        let script = bitcoin::Script::from(bytes);
        Ok(Script(script))
    }
}

#[derive(Encode, Decode)]
pub struct Outpoint {
    txid: [u8; 32],
    index: u32,
}

impl From<bitcoin::OutPoint> for Outpoint {
    fn from(outpoint: bitcoin::OutPoint) -> Self {
        Outpoint {
            txid: outpoint.txid.as_hash().into_inner(),
            index: outpoint.vout,
        }
    }
}
