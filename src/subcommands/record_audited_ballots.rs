//! # Command: Record Audited Ballots
//!
//! `record_audited_ballots` takes a file of ballots spoiled during the public
//! audit and records them as part of the secured poll configuration.

use super::*;

#[derive(Debug, Clone, Deserialize)]
pub struct AuditedBallotRecord {
    serial: BallotSerial
}

pub fn record_audited_ballots(pollconf_filename: &str, audited_ballots_filename: &str, force: bool, xxn: &str) -> Result<()> {
    let pollconf_path = Path::new(pollconf_filename);

    // Read poll configuration file.
    let mut secured_poll_configuration = read_poll_configuration_file(pollconf_filename)?;

    // Reconstruct the Poll Master Key from the trustee passwords.
    let (poll_master_key, aead_pmk) = read_poll_master_key(&secured_poll_configuration);

    // Ensure the data directory exists.
    let datadir_path = ensure_poll_data_directory_exists(&secured_poll_configuration, &aead_pmk)?;

    // Decrypt poll configuration state.
    let pollconf_aead_values = secured_poll_configuration.encrypted_poll_configuration.values()?;
    let serialized_pollconf = aead_decrypt(&aead_pmk, &pollconf_aead_values)?;
    let mut pollconf: PollConfiguration = serde_yaml::from_slice(&serialized_pollconf).unwrap();
    
    assert!(pollconf.poll_state.summands_drawn,
        "Content for public audit must be printed before marking audited ballots.");
    assert!(!pollconf.poll_state.ceremony_conducted || force,
        "Audited ballots already recorded. To re-record, pass --force.");

    // Derive the poll secrets.
    let poll_secrets: PollSecrets = PollSecrets::derive(&poll_master_key);
    
    // Record audited ballots.
    let audited_ballots = {
        let audited_ballots_path = Path::new(audited_ballots_filename);
        let mut csvreader = csv::Reader::from_path(audited_ballots_path)?;
        let records = csvreader.deserialize::<AuditedBallotRecord>();
        records.filter_map(|row| {
                let record: AuditedBallotRecord = row.unwrap();
                if record.serial < pollconf.num_ballots { Some(record.serial) }
                else { None }
            }).collect::<Vec<BallotSerial>>()
    };
    pollconf.audited_ballots = Some(audited_ballots.iter()
        .map(|serial| serial.to_string())
        .collect());

    // Post the Column Planes.
    let column_planes: Vec<Plane> = generate_column_planes(
        &poll_secrets,
        NUMBER_OF_PLANES,
        2 * pollconf.num_ballots,
        pollconf.num_decoys)?;
    // Filter planes.
    column_planes.iter().enumerate()
        .for_each(|(n, plane)| {
            let posted_planes_path = {
                let mut pathbuf = PathBuf::new();
                pathbuf.push(&datadir_path);
                pathbuf.push(format!("print_audit_plane_{:02}", n+1));
                pathbuf.set_extension("csv");
                pathbuf.into_boxed_path()
            };
            let posted_keys_path = {
                let mut pathbuf = PathBuf::new();
                pathbuf.push(&datadir_path);
                pathbuf.push(format!("print_audit_plane_{:02}_keys", n+1));
                pathbuf.set_extension("csv");
                pathbuf.into_boxed_path()
            };
            let psecrets = poll_secrets.plane_secrets[n].resolve(plane.len());
            let filter = PlaneFilter::from(&psecrets.col1_keys, &psecrets.col3_keys)
                .decrypt_serials(&audited_ballots);

            let permuted_plane = plane.decrypt(&filter).permute(&psecrets.permutation);
            let mut csvwriter = csv::Writer::from_path(posted_planes_path).unwrap();
            permuted_plane.rows.iter()
                .for_each(|rec| {
                    csvwriter.serialize(rec.serializable(pollconf.num_ballots)).unwrap();
                });
            
            let permuted_filter = filter.permute(&psecrets.permutation);
            let mut csvwriter = csv::Writer::from_path(posted_keys_path).unwrap();
            permuted_filter.serializable().iter()
                .for_each(|rec| {
                    csvwriter.serialize(rec).unwrap();
                });
        });

    // Update the poll state.
    pollconf.poll_state.ceremony_conducted = true;
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

    blockchain::commit(xxn, pollconf, column_planes)?;

    Ok(())
}

