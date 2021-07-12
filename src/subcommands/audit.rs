//! Blockchain audit
//! 
//! Count votes present in blockchain with address of poll

use super::*;
use crate::blockchain::audit_votes;

pub fn blockchain_audit(pollconf_filename: &str, xxn_filename: &str) -> Result <()> {
    // Read poll configuration file.
    let secured_poll_configuration = read_poll_configuration_file(pollconf_filename)?;

    // Reconstruct the Poll Master Key from the trustee passwords.
    let (poll_master_key, aead_pmk) = read_poll_master_key(&secured_poll_configuration);

    // Decrypt poll configuration state.
    let pollconf_aead_values = secured_poll_configuration.encrypted_poll_configuration.values()?;
    let serialized_pollconf = aead_decrypt(&aead_pmk, &pollconf_aead_values)?;
    let pollconf: PollConfiguration = serde_yaml::from_slice(&serialized_pollconf).unwrap();

    assert!(pollconf.poll_state.summands_drawn,
        "Summands must be drawn to generate voters and print content for public audit.");

    // Derive the poll secrets.
    let poll_secrets: PollSecrets = PollSecrets::derive(&poll_master_key);

    // Generate the Ballots.
    let serials: Vec<BallotSerial> = (0..pollconf.num_ballots).collect();
    let votecodes: Vec<VoteCode> = generate_votecodes(
        poll_secrets.votecode_root,
        2 * pollconf.num_ballots);

    // Regenerate ballots
    let ballots = generate_ballots(&serials, &votecodes);
    audit_votes(ballots, xxn_filename)
}