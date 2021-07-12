//! # Seventh-Estate Application
//!
//! Input Files:
//! * Poll Configuration (YAML)
//! * Voter Roster (CSV)
//! * Spoiled Ballots (CSV)
//! * Votes (CSV)
//!
//! Output Files:
//! * Secure Poll Configuration (YAML)
//! * Address Labels (CSV)
//! * Ballot Information (CSV)
use clap::{Arg, App, SubCommand};
use seventh_estate::subcommands::*;
use tokio;

type Exception = Box<dyn std::error::Error + 'static>;

#[tokio::main]
async fn main() -> Result<(), Exception> {
    let matches = App::new("Seventh-Estate")
        .about("Seventh-Estate Poll Manager")
        .version("1.0")
        .subcommand(SubCommand::with_name("new")
            .about("Create a new poll.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true)))
        .subcommand(SubCommand::with_name("bind-roster")
            .about("Bind roster to poll.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("roster_file")
                .long("roster")
                .value_name("FILE")
                .help("Voter roster CSV file.")
                .required(true))
            .arg(Arg::with_name("disable_voter_privacy")
                .long("disable-voter-privacy")
                .help("Commit roster with full voter name and address information.")
                .required(false))
            .arg(Arg::with_name("force")
                .long("force")
                .help("Force a re-commit of the voter roster.")
                .required(false)))
        .subcommand(SubCommand::with_name("step1")
            .about("Step 1: Generate initial commitments.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("force")
                .long("force")
                .help("Force a re-commit of the initial commitments.")
                .required(false)))
        .subcommand(SubCommand::with_name("step2")
            .about("Step 2: Generate drawn summands.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("drawn_summands_seed")
                .short("s")
                .long("seed")
                .value_name("HEX")
                .help("Seed value as hexadecimal string of bytes.")
                .required(true))
            .arg(Arg::with_name("force")
                .long("force")
                .help("Force a re-generation of the drawn summands.")
                .required(false)))
        .subcommand(SubCommand::with_name("step3")
            .about("Step 3: Generate address labels and ballot information.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("address_label")
                .long("addresses")
                .value_name("FILE")
                .help("Address label CSV file.")
                .required(true))
            .arg(Arg::with_name("ballot_information")
                .long("ballots")
                .value_name("FILE")
                .help("Ballot information CSV file.")
                .required(true)))
        .subcommand(SubCommand::with_name("step4")
            .about("Step 4: Record audited (spoiled) ballots.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("audited_ballots")
                .long("serial-file")
                .value_name("FILE")
                .help("Ballot serials LIST file.")
                .required(true))
            .arg(Arg::with_name("xxn_config")
                .short("x")
                .long("xxn")
                .value_name("FILE")
                .help("XX Network configuration file")
                .required(true)))
        .subcommand(SubCommand::with_name("step5")
            .about("Step 5: --VOTE-- (This command does nothing.)"))
        .subcommand(SubCommand::with_name("step6")
            .about("Step 6: Record votes.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("votes_file")
                .long("votes")
                .value_name("FILE")
                .help("Votes recorded CSV file.")
                .required(true))
            .arg(Arg::with_name("force")
                .long("force")
                .help("Force an overwrite of the recorded votes.")
                .required(false)))
        .subcommand(SubCommand::with_name("step7")
            .about("Step 7: Generate audited plane columns.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("tally_audit_seed")
                .short("s")
                .long("seed")
                .value_name("HEX")
                .help("Seed value as hexadecimal string of bytes.")
                .required(true))
            .arg(Arg::with_name("force")
                .long("force")
                .help("Force a re-generation of the audited planes columns.")
                .required(false)))
        .subcommand(SubCommand::with_name("step8")
            .about("Step 8: Generated decrypted plane columns.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("force")
                .long("force")
                .help("Force a re-decrypt of the plane columns.")
                .required(false)))
        .subcommand(SubCommand::with_name("sign")
            .about("Generate signature for a file to publish.")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("File for which to generate a signature.")
                .required(true)))
        .subcommand(SubCommand::with_name("gen")
            .about("Generate proof of inclusion for data in YAML format.")
            .arg(Arg::with_name("merkle_tree")
                .short("m")
                .long("merkle")
                .value_name("FILE")
                .help("Merkle tree in YAML format.")
                .required(true))
            .arg(Arg::with_name("data")
                .short("d")
                .long("data")
                .value_name("STRING")
                .help("Data to generate proof of.")
                .required(true)))
        .subcommand(SubCommand::with_name("validate")
            .about("Validate proof of inclusion given in YAML format.")
            .arg(Arg::with_name("inclusion_proof")
                .short("p")
                .long("proof")
                .value_name("FILE")
                .help("Proof of inclusion in YAML format (Given by gen subcommand).")
                .required(true)))
        .subcommand(SubCommand::with_name("audit")
            .about("Blockchain audit, count votes in blockchain")
            .arg(Arg::with_name("poll_configuration")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Poll configuration YAML file.")
                .required(true))
            .arg(Arg::with_name("xxn_config")
                .short("x")
                .long("xxn")
                .value_name("FILE")
                .help("XX Network configuration file")
                .required(true)))
        .get_matches();

    stderrlog::new().verbosity(4).init().unwrap();

    match matches.subcommand() {
        ("new", Some(arguments)) => {
            create_new_poll(
                arguments.value_of("poll_configuration").unwrap())?;
        },
        ("bind-roster", Some(arguments)) => {
            bind_roster(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("roster_file").unwrap(),
                0 < arguments.occurrences_of("disable_voter_privacy"),
                0 < arguments.occurrences_of("force"))?;
        },
        ("step1", Some(arguments)) => {
            generate_poll_commitments(
                arguments.value_of("poll_configuration").unwrap(),
                0 < arguments.occurrences_of("force"))?;
        },
        ("step2", Some(arguments)) => {
            generate_drawn_summands(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("drawn_summands_seed").unwrap(),
                0 < arguments.occurrences_of("force"))?;
        },
        ("step3", Some(arguments)) => {
            generate_print_files(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("address_label").unwrap(),
                arguments.value_of("ballot_information").unwrap())?;
        },
        ("step4", Some(arguments)) => {
            record_audited_ballots(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("audited_ballots").unwrap(),
                0 < arguments.occurrences_of("force"),
            arguments.value_of("xxn_config").unwrap())?;
        },
        ("step6", Some(arguments)) => {
            record_votes(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("votes_file").unwrap(),
                0 < arguments.occurrences_of("force"))?;
        },
        ("step7", Some(arguments)) => {
            generate_tally_audit(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("tally_audit_seed").unwrap())?;
        },
        ("step8", Some(arguments)) => {
            generate_poll_revelations(
                arguments.value_of("poll_configuration").unwrap(),
                0 < arguments.occurrences_of("force"))?;
        },
        ("sign", Some(arguments)) => {
            sign_document(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("file").unwrap())?;
        },
        ("gen", Some(arguments)) => {
            generate_proof(
                arguments.value_of("merkle_tree").unwrap(),
                arguments.value_of("data").unwrap())?;

        },
        ("validate", Some(arguments)) => {
            validate_proof(
                arguments.value_of("inclusion_proof").unwrap())?;

        },
        ("audit", Some(arguments)) => {
            blockchain_audit(
                arguments.value_of("poll_configuration").unwrap(),
                arguments.value_of("xxn_config").unwrap())?;
        }
        _ => ()
    }

    Ok(())
}

