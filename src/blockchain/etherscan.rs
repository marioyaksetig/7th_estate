use serde::Deserialize;
use crate::untagged::VoteCode;
use crate::Result;

pub fn slice_as_vote(xs: &[u8]) -> &[u8; 20] {
    slice_as_array!(xs, [u8; 20]).expect("bad votecode length")
}

#[derive(Debug, Deserialize)]
pub struct SubmittedVote {
    // ballot: String,
    votecode: String
}

impl SubmittedVote {
    pub fn to_votecode(&self) -> Result<VoteCode> {
        // Remove '-'
        let votecode: Vec<&str> = self.votecode.split('-').collect();
        let votecode: String = votecode.join("");
        let votecode: Vec<u8> = votecode.chars().map(|digit| {
            digit.to_digit(10).unwrap() as u8
        }).collect();


        let votecode: &[u8] = &votecode[..];
        let votecode = slice_as_vote(votecode);

        Ok(*votecode)
    }
    /*
    pub fn to_serial(&self) -> std::result::Result<usize, std::num::ParseIntError> {
        self.ballot.parse::<usize>()
    }
    */
}

#[derive(Debug, Deserialize)]
pub struct Response {
    status: String,
    message: String,
    pub result: Vec<Transaction>
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    block_number: String,
    time_stamp: String,
    hash: String,
    nonce: String,
    block_hash: String,
    transaction_index: String,
    pub from: String,
    to: String,
    value: String,
    gas: String,
    gas_price: String,
    is_error: String,

    #[serde(rename="txreceipt_status")]
    txreceipt_status: String,
    pub input: String,
    contract_address: String,
    cumulative_gas_used: String,
    gas_used: String,
    confirmations: String
}