use clap::{Parser, Subcommand};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::path::PathBuf;
use std::process;

// mod clipboard;
mod enpass;
mod unlock;

const PIN_MIN_LENGTH: usize = 8;
const PIN_DEFAULT_KDF_ITER_COUNT: u32 = 100000;

// Version will be set during build
static VERSION: &str = "dev";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to your Enpass vault
    #[arg(long, value_name = "PATH")]
    vault: Option<PathBuf>,

    /// The type of your card (password, ...)
    #[arg(long, default_value = "password")]
    r#type: String,

    /// Path to your Enpass vault keyfile
    #[arg(long)]
    keyfile: Option<PathBuf>,

    /// The log level from debug (5) to error (1)
    #[arg(long, default_value = "info")]
    log: String,

    /// Output data in JSON format
    #[arg(long)]
    json: bool,

    /// Disable prompts and fail instead
    #[arg(long)]
    non_interactive: bool,

    /// Enable PIN
    #[arg(long)]
    pin: bool,

    /// Combines filters with AND instead of default OR
    #[arg(long)]
    and: bool,

    /// Sort the output by title and username
    #[arg(long)]
    sort: bool,

    /// Show trashed items
    #[arg(long)]
    trashed: bool,

    /// Use primary X selection instead of clipboard
    #[arg(long)]
    clipboard_primary: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show version information
    Version,

    /// Test vault access without performing operations
    Dryrun,

    /// List vault entries
    List {
        /// Optional filters for entries
        filters: Vec<String>,
    },

    /// Show entries including passwords
    Show {
        /// Optional filters for entries
        filters: Vec<String>,
    },

    /// Copy password to clipboard
    Copy {
        /// Filters to select a unique entry
        filters: Vec<String>,
    },

    /// Print password to stdout
    Pass {
        /// Filters to select a unique entry
        filters: Vec<String>,
    },

    /// Launch interactive UI
    Ui {
        /// Optional filters for entries
        filters: Vec<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct CardData {
    title: String,
    login: String,
    category: String,
    label: String,
    r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

fn prompt(args: &Args, msg: &str) -> String {
    if !args.non_interactive {
        eprint!("Enter {}: ", msg);
        rpassword::read_password().unwrap_or_else(|err| {
            error!("Could not prompt for {}: {}", msg, err);
            process::exit(1);
        })
    } else {
        String::new()
    }
}

fn sort_entries(cards: &mut Vec<enpass::card::Card>) {
    // Sort by username preserving original order
    cards.sort_by(|a, b| a.subtitle.to_lowercase().cmp(&b.subtitle.to_lowercase()));
    // Sort by title, preserving username order
    cards.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
}

fn prepare_card_data(
    cards: &[enpass::card::Card],
    include_decrypted: bool,
    args: &Args,
) -> Result<Vec<CardData>, Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    for card in cards {
        if card.is_trashed() && !args.trashed {
            continue;
        }

        let mut card_data = CardData {
            title: card.title.clone(),
            login: card.subtitle.clone(),
            category: card.category.clone(),
            label: card.label.clone(),
            r#type: card.card_type.clone(),
            password: None,
        };

        if include_decrypted {
            card_data.password = Some(card.decrypt()?);
        }

        data.push(card_data);
    }

    Ok(data)
}

fn output_data_or_log(data: &[CardData], args: &Args) {
    if args.json {
        println!("{}", serde_json::to_string(data).unwrap());
    } else {
        for card in data {
            info!(
                "title: {}  login: {}  category: {}  label: {}",
                card.title, card.login, card.category, card.label
            );
        }
    }
}

fn list_entries(
    vault: &enpass::vault::Vault,
    args: &Args,
    filters: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Listing entries of type: {}", args.r#type);
    println!("Using filters: {:?}", filters);
    let mut cards = vault.get_entries(&args.r#type, filters)?;

    if args.sort {
        sort_entries(&mut cards);
    }

    let data = prepare_card_data(&cards, false, args)?;
    output_data_or_log(&data, args);

    Ok(())
}

fn show_entries(
    vault: &enpass::vault::Vault,
    args: &Args,
    filters: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cards = vault.get_entries(&args.r#type, filters)?;

    if args.sort {
        sort_entries(&mut cards);
    }

    let data = prepare_card_data(&cards, true, args)?;
    output_data_or_log(&data, args);

    Ok(())
}

fn copy_entry(
    vault: &enpass::vault::Vault,
    args: &Args,
    filters: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let card = vault.get_entry(&args.r#type, filters, true)?;
    let decrypted = card.decrypt()?;

    if args.clipboard_primary {
        // clipboard::set_primary(true);
        debug!("Primary X selection enabled");
    }

    // clipboard::write_all(&decrypted)?;
    Ok(())
}

fn entry_password(
    vault: &enpass::vault::Vault,
    args: &Args,
    filters: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let cards = vault.get_entries(&args.r#type, filters)?;

    for (index, card) in cards.iter().enumerate() {
        println!(
            "[{}] title: {}  login: {}",
            index, card.title, card.subtitle
        );
    }

    print!("Select entry number: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let selection: usize = input.trim().parse().unwrap_or_else(|_| {
        error!("Invalid selection");
        process::exit(1);
    });

    let card = cards.get(selection).unwrap_or_else(|| {
        error!("Selection out of range");
        process::exit(1);
    });

    let decrypted = card.decrypt()?;
    println!("{}", decrypted);
    Ok(())
}

fn ui_mode(
    vault: &enpass::vault::Vault,
    args: &Args,
    filters: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cards = vault.get_entries(&args.r#type, filters)?;

    if args.sort {
        sort_entries(&mut cards);
    }

    // Implementation for terminal UI would go here
    // For simplicity, we'll just show a message that this is not implemented
    println!("UI mode not implemented in this Rust version");

    Ok(())
}

fn assemble_vault_credentials(
    args: &Args,
    store: Option<&mut unlock::securestore::SecureStore>,
) -> enpass::vault::VaultCredentials {
    let mut credentials = enpass::vault::VaultCredentials {
        password: env::var("MASTERPW").ok(),
        keyfile_path: args.keyfile.clone(),
        db_key: None,
    };

    if !credentials.is_complete() && store.is_some() {
        if let Ok(db_key) = store.unwrap().read() {
            credentials.db_key = db_key;
            debug!("Read credentials from store");
        } else {
            error!("Could not read credentials from store");
            process::exit(1);
        }
    }

    if !credentials.is_complete() {
        credentials.password = Some(prompt(args, "vault password"));
        println!("{:?}", credentials.password);
    }

    credentials
}

fn initialize_store(
    args: &Args,
    vault_path: &PathBuf,
) -> Result<unlock::securestore::SecureStore, Box<dyn std::error::Error>> {
    let mut store =
        unlock::securestore::SecureStore::new(vault_path.file_name().unwrap().to_str().unwrap())?;

    let pin = env::var("ENP_PIN").unwrap_or_else(|_| prompt(args, "PIN"));

    if pin.len() < PIN_MIN_LENGTH {
        error!("PIN too short");
        process::exit(1);
    }

    let pepper = env::var("ENP_PIN_PEPPER").unwrap_or_default();

    let pin_kdf_iter_count = env::var("ENP_PIN_ITER_COUNT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(PIN_DEFAULT_KDF_ITER_COUNT);

    store.generate_passphrase(&pin, &pepper, pin_kdf_iter_count)?;

    Ok(store)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    // Set up logging based on the log level
    log::set_max_level(log::LevelFilter::Trace);

    // set log level

    match args.command {
        Some(Commands::Version) => {
            println!(
                "{} arch={} os={} version={}",
                env::args()
                    .next()
                    .unwrap_or_else(|| String::from("enpass-cli")),
                std::env::consts::ARCH,
                std::env::consts::OS,
                VERSION
            );
            return Ok(());
        }
        None => {
            let _ = clap::Command::new("enpass-cli").print_help();
            return Ok(());
        }
        _ => {}
    }

    let vault_path = match &args.vault {
        Some(path) => path.clone(),
        None => {
            error!("Vault path must be provided");
            process::exit(1);
        }
    };

    let mut vault = enpass::vault::Vault::new(&vault_path)?;
    vault.filter_and = args.and;

    let mut store = if args.pin {
        debug!("PIN enabled, using store");
        Some(initialize_store(&args, &vault_path)?)
    } else {
        debug!("PIN disabled");
        None
    };

    debug!("Assembling vault credentials");
    let credentials = assemble_vault_credentials(&args, store.as_mut());
    debug!("Opening vault");

    vault.open(&credentials)?;
    debug!("Opened vault");

    let result = match &args.command {
        Some(Commands::Dryrun) => {
            debug!("Dry run complete");
            Ok(())
        }
        Some(Commands::List { filters }) => list_entries(&vault, &args, filters),
        Some(Commands::Show { filters }) => show_entries(&vault, &args, filters),
        Some(Commands::Copy { filters }) => copy_entry(&vault, &args, filters),
        Some(Commands::Pass { filters }) => entry_password(&vault, &args, filters),
        Some(Commands::Ui { filters }) => ui_mode(&vault, &args, filters),
        _ => {
            error!("Unknown command");
            process::exit(1);
        }
    };

    // Store credentials if needed
    if let Some(mut store) = store {
        if let Some(db_key) = &credentials.db_key {
            store.write(db_key)?;
        }
    }

    result
}
