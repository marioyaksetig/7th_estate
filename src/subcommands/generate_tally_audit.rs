//! # Command: Generate Tally AuditRecord Votes
//!

use super::*;



pub fn generate_tally_audit(pollconf_filename: &str, seed: &str) -> Result<()> {
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
    
    assert!(pollconf.poll_state.votes_committed,
        "Votes must be committed prior to auditing the tally.");

    // Bind the audited columns seed.
    let audited_columns_seed: Vec<u8> = hex::decode(seed)?;
    assert!(audited_columns_seed.len() == CSPRNGSeed::SIZE,
        "Seed for Audited Columns must be {} bytes long.", CSPRNGSeed::SIZE);
    pollconf.audited_columns_seed = Some(seed.to_owned());

    // Draw the Audited Column.
    let audited_columns_path = {
        let mut pathbuf = PathBuf::new();
        pathbuf.push(&datadir_path);
        pathbuf.push("audited_columns");
        pathbuf.set_extension("yaml");
        pathbuf.into_boxed_path()
    };
    let audited_columns: Vec<usize> = {
        let seed = CSPRNGSeed::from_vec(&audited_columns_seed);
        let mut prng = CSPRNG::from_csprng_seed(seed);
        (0..NUMBER_OF_PLANES).into_iter().map(|_| prng.gen_range(0, 2)).collect()
    };
    let audited_columns_readable: Vec<String> = {
        audited_columns.iter().enumerate().map(|(n, &bit)| {
            if bit == 0 { format!("Plane [{}]: Column [1]", n+1) }
            else { format!("Plane [{}]: Column [3]", n+1) }
        }).collect()
    };
    serde_yaml::to_writer(
        File::create(audited_columns_path)?,
        &audited_columns_readable)?;

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

