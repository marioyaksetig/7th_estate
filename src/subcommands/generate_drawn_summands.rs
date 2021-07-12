//! # Command: Generate Drawn Summands
//!
//! `generate_drawn_summands` takes a verifiable random seed and binds it to
//! the secured poll configuration. The command also outputs a file with the
//! drawn sumamnds in case the poll trustees wish to publish the generated
//! values.

use super::*;


pub fn generate_drawn_summands(pollconf_filename: &str, seed: &str, force: bool) -> Result<()> {
    let pollconf_path = Path::new(pollconf_filename);

    // Read poll configuration file.
    let mut secured_poll_configuration = read_poll_configuration_file(pollconf_filename)?;

    // Reconstruct the Poll Master Key from the trustee passwords.
    let (_poll_master_key, aead_pmk) = read_poll_master_key(&secured_poll_configuration);

    // Ensure the data directory exists.
    let datadir_path = ensure_poll_data_directory_exists(&secured_poll_configuration, &aead_pmk)?;

    // Decrypt poll configuration state.
    let pollconf_aead_values = secured_poll_configuration.encrypted_poll_configuration.values()?;
    let serialized_pollconf = aead_decrypt(&aead_pmk, &pollconf_aead_values)?;
    let mut pollconf: PollConfiguration = serde_yaml::from_slice(&serialized_pollconf).unwrap();
   
    assert!(pollconf.poll_state.summands_committed,
        "Summands must be committed prior to generating drawn summands.");
    assert!(pollconf.poll_state.columns_committed || force,
        "Columns must be committed prior to generating drawn summands.");
    assert!(!pollconf.poll_state.summands_drawn || force,
        "Summands already drawn. To re-draw, pass --force.");
    
    // Bind the drawn summands seed.
    let drawn_summands_seed: Vec<u8> = hex::decode(seed)?;
    assert!(drawn_summands_seed.len() == CSPRNGSeed::SIZE,
        "Seed for Drawn Summands must be {} bytes long.", CSPRNGSeed::SIZE);
    pollconf.drawn_summands_seed = Some(seed.to_owned());

    // Draw the Summands.
    let drawn_summands_path = {
        let mut pathbuf = PathBuf::new();
        pathbuf.push(&datadir_path);
        pathbuf.push("drawn_summands");
        pathbuf.set_extension("yaml");
        pathbuf.into_boxed_path()
    };
    let drawn_summands = DrawnSummands::from_csprng(
        CSPRNGSeed::from_vec(&drawn_summands_seed),
        pollconf.num_ballots,
        pollconf.voter_roster_size);
    debug!("{:#?}", drawn_summands);
    serde_yaml::to_writer(
        File::create(drawn_summands_path)?,
        &drawn_summands)?;

    // Update the poll state.
    pollconf.poll_state.summands_drawn = true;
    // Re-encrypt the poll configuration.
    let serialized_pollconf = serde_yaml::to_string(&pollconf)?;
    let secure_serialized_pollconf = AEADString::from_values(
        aead_encrypt(&aead_pmk,
                     Vec::new(),
                     serialized_pollconf.as_bytes().to_vec())?);
    // Save the poll configuration.
    secured_poll_configuration.encrypted_poll_configuration = secure_serialized_pollconf;
    serde_yaml::to_writer(
        File::create(pollconf_path)?,
        &secured_poll_configuration)?;

    Ok(())
}

