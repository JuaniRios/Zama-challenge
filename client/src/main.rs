use clap::{Parser, Subcommand};
use itertools::Itertools;
use merkle_tree::{verify_proof, MerkleProof, MerkleTree};
use sp_crypto_hashing::blake2_256;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use dirs::config_dir;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Sets the path to your shh key used for encrypting your files
    SetSSHKeyLocation { key_path: String },
    /// Shows your set path to your ssh key
    ShowSSHKeyLocation,
    /// Encrypts all the files in the specified directory, and generates a Merkle tree over them. Stores the merkle root and the encrypted files.
    MerkelizeFiles { folder_path: String },
    /// Shows all the merkle roots created by each MerkelizeFiles command. Useful to later delete the encrypted files.
    ShowMerkleRoots,
    /// Deletes the encrypted files associated with a merkle root. Should be done only if the merkle tree was saved somewhere else.
    DeleteEncryptedFiles { merkle_root: String },
    /// Restores an encrypted file from the specified merkle root. The merkle proof is used to verify the file's integrity.
    RestoreEncryptedFile { file: Vec<u8>, proof: MerkleProof},
    /// Decrypts all the files associated with a merkle root.
    DecryptFiles,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ShowSSHKeyLocation  => {
            // Get the user's configuration directory
            let mut config_path = config_dir().expect("Failed to find config directory");
            config_path.push("my-cli"); // Name of your application
            fs::create_dir_all(&config_path).expect("Failed to create config directory");

            // Append the configuration file name
            config_path.push("config.conf");

            // Read the key path from the configuration file
            let key_path = fs::read_to_string(&config_path).expect("Failed to read key path");

            println!("Key path: {}", key_path);
        }
        Commands::SetSSHKeyLocation { key_path } =>  {
            // Get the user's configuration directory
            let mut config_path = config_dir().expect("Failed to find config directory");
            config_path.push("my-cli"); // Name of your application
            fs::create_dir_all(&config_path).expect("Failed to create config directory");

            // Append the configuration file name
            config_path.push("config.conf");

            // Save the key path to the configuration file
            fs::write(&config_path, key_path).expect("Failed to write key path");

            println!("Key path saved to: {}", config_path.display());
        }
        Commands::MerkelizeFiles { folder_path } => {
            // Get the current directory

            // Initialize a HashMap to store file names and their contents
            let mut files: Vec<String> = Vec::new();

            // Read all files in the current directory
            for entry in fs::read_dir(current_dir).expect("Failed to read directory") {
                let entry = entry.expect("Failed to get directory entry");
                let path = entry.path();

                // Check if the entry is a file
                if path.is_file() {
                    let content = fs::read_to_string(&path).expect("Failed to read file");

                    files.push(content)
                }
            }
        }
    }





}
