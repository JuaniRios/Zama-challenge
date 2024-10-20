use clap::{Parser, Subcommand};
use crypto;
use dirs::config_dir;
use ed25519_dalek::ed25519::signature::Keypair;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use itertools::Itertools;
use merkle_tree::{HashDigest, MerkleProof};
use reqwest::Client;
use serde::Serialize;
use sp_crypto_hashing::blake2_256;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ShowConfigFolder,
    /// Sets the path to your SSH key used for encrypting your files
    SetSSHKeyLocation {
        /// Path to the SSH private key
        key_path: String,
    },
    /// Shows your set path to your SSH key
    ShowSSHKeyLocation,
    /// Encrypts all the files in the specified directory, and generates a Merkle tree over them. Stores the Merkle root and the encrypted files.
    EncryptAndMerkelizeFiles {
        /// Path to the folder containing files to encrypt
        folder_path: String,
    },
    /// Shows all the Merkle roots created by each MerkelizeFiles command. Useful to later delete the encrypted files.
    ShowMerkleRoots,
    /// Deletes the encrypted files associated with a Merkle root. Should be done only if the Merkle tree was saved somewhere else.
    SendToCloudAndDeleteEncryptedFiles {
        /// Merkle root of the files to delete
        merkle_root: String,
    },
    /// Restores an encrypted file from the specified Merkle root. The Merkle proof is used to verify the file's integrity.
    RestoreEncryptedFileFromCloud {
        merkle_root: String,
        file_index: u32,
    },
    /// Decrypts all the files associated with a merkle root.
    DecryptFiles {
        /// Merkle root of the files to decrypt
        merkle_root: String,
    },
}

#[derive(Serialize)]
struct EncryptedFileRequest {
    files: Vec<Vec<u8>>,
    verifying_key: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct FileRequest {
    index: usize,
    merkle_root: String, // hex encoded hash digest ([u8; 32])
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ShowConfigFolder => {
            println!("Config folder: {}", get_config_file_path().display());
        }
        /// Save the SSH key path to the configuration file. This key will be used to derive a symmetric key for file encryption.
        /// Normally this would point to /home/user/.ssh/id_ed25519 or similar.
        Commands::SetSSHKeyLocation { key_path } => {
            set_ssh_key_path(key_path);
        }

        /// Read the SSH key path from the configuration file.
        Commands::ShowSSHKeyLocation => {
            println!("Saved key path: {}", get_ssh_key_path());
        }
        /// Encrypts the files with a derived key from the SSH private key, and stores the Merkle root and encrypted files
        Commands::EncryptAndMerkelizeFiles { folder_path } => {
            encrypt_and_merkelize_files(&folder_path);
        }
        /// Shows all the Merkle roots created by each MerkelizeFiles command
        Commands::ShowMerkleRoots => {
            show_merkle_roots();
        }
        /// Deletes the encrypted files associated with a Merkle root
        Commands::SendToCloudAndDeleteEncryptedFiles { merkle_root } => {
            send_to_cloud_and_delete_encrypted_files(merkle_root).await;
        }
        /// Restores an encrypted file from the specified Merkle root using a Merkle proof
        Commands::RestoreEncryptedFileFromCloud {
            merkle_root,
            file_index,
        } => {
            restore_encrypted_file_from_cloud(merkle_root, file_index).await;
        }
    };
}

fn set_ssh_key_path(key_path: String) {
    let config_path = get_config_file_path();
    fs::write(&config_path, &key_path).expect("Failed to write key path");
    println!("Key path saved to: {}", config_path.display());
}

// Helper function to get the SSH key path from the configuration file
fn get_ssh_key_path() -> String {
    let mut config_path = get_config_file_path();
    if !config_path.exists() {
        panic!("SSH key path not set. Please run SetSSHKeyLocation.");
    }
    let key_path_str = fs::read_to_string(&config_path).expect("Failed to read key path");
    key_path_str
}

// Helper function to get the configuration file path
fn get_config_file_path() -> PathBuf {
    let mut config_path = config_dir().expect("Failed to find config directory");
    config_path.push("my-cli"); // Name of your application
    fs::create_dir_all(&config_path).expect("Failed to create config directory");
    config_path.push("config.conf");
    config_path
}

// Function to get the path to the merkle_roots folder
fn get_merkle_roots_folder_path() -> PathBuf {
    let mut path = config_dir().expect("Failed to find config directory");
    path.push("my-cli");
    fs::create_dir_all(&path).expect("Failed to create config directory");
    path.push("merkle_roots");
    path
}

fn encrypt_and_merkelize_files(folder_path: &str) {
    let symmetric_encryption_key =
        crypto::load_ed25519_private_key_and_derive_symmetric_key(get_ssh_key_path())
            .expect("Failed to generate the symmetric encryption key");

    // Create temp folder inside the merkle_roots dir which will be later renamed to the merkle root
    let temp_folder = get_merkle_roots_folder_path().join("temp");
    let encrypted_files_folder = temp_folder.join("encrypted_files");
    fs::create_dir_all(&encrypted_files_folder).expect("Failed to create encrypted files folder");

    // Encrypt all files and store them in a folder inside the merkle_roots dir.
    for (index, entry) in fs::read_dir(folder_path)
        .expect("Failed to read directory")
        .enumerate()
    {
        let file = entry.expect("Failed to get file");
        let file_path = file.path(); // Keep the original file path
        let file_path_str = file_path.to_string_lossy().to_string();

        // Create an output file path with the name "1", "2", "3", etc. based on the index
        let output_file_name = format!("{}", index + 1); // Create sequential file names starting from 1
        let output_path_str = encrypted_files_folder
            .join(output_file_name) // Create file inside encrypted_files folder with sequential names
            .to_string_lossy()
            .to_string();

        // Encrypt the file
        crypto::encrypt_file(&file_path_str, &output_path_str, &symmetric_encryption_key)
            .expect("Failed to encrypt file");
    }

    // Calculate the merkle root of these files, and rename the folder to the merkle root
    let merkle_tree = merkle_tree::construct_tree_from_folder_path(
        encrypted_files_folder
            .to_str()
            .expect("Failed to convert temp folder path to str"),
    );
    let merkle_root = merkle_tree.root();
    let merkle_root_hex_encoded = hex::encode(merkle_root);

    // Rename temp folder to merkle root
    let merkle_root_folder = get_merkle_roots_folder_path().join(merkle_root_hex_encoded);
    fs::rename(&temp_folder, &merkle_root_folder).expect("Failed to rename temp folder");
}

// Function to show all stored Merkle roots
fn show_merkle_roots() {
    let merkle_roots_path = get_merkle_roots_folder_path();

    if !merkle_roots_path.exists() {
        println!("No Merkle roots found.");
        return;
    }

    // Read the contents of the merkle_roots directory
    for entry in fs::read_dir(&merkle_roots_path).expect("Failed to read directory") {
        let entry = entry.expect("Failed to get entry");
        let merkle_root_folder = entry.path();

        if merkle_root_folder.is_dir() {
            println!(
                "Merkle Root: {}",
                merkle_root_folder.file_name().unwrap().to_string_lossy()
            );
        }
    }
}

async fn send_to_cloud_and_delete_encrypted_files(merkle_root: String) {
    let client = Client::new();
    let url = "http://127.0.0.1:8080/upload"; // Modify with the correct server URL

    // For this example, you would gather the encrypted files and public key details as needed
    let merkle_root_folder = get_merkle_roots_folder_path().join(merkle_root);
    let encrypted_files_folder = merkle_root_folder.join("encrypted_files");
    let encrypted_files: Vec<Vec<u8>> = fs::read_dir(&encrypted_files_folder)
        .expect("Failed to read directory")
        .map(|entry| {
            let entry = entry.expect("Failed to get entry");
            let file_path = entry.path();
            let mut file = File::open(&file_path).expect("Failed to open file");
            let mut file_content = Vec::new();
            file.read_to_end(&mut file_content)
                .expect("Failed to read file content");
            file_content
        })
        .collect();

    let signing_key = crypto::load_ed25519_signing_key_from_path(get_ssh_key_path())
        .expect("Couldn't read the ed25519 private key file");

    // Verify the signature
    let file_hashes: Vec<[u8; 32]> = encrypted_files
        .iter()
        .map(|file| blake2_256(file.as_slice())) // Example hash function, change as needed
        .collect();
    let files_combined_hash = blake2_256(&file_hashes.concat());

    let signature = signing_key.sign(files_combined_hash.as_slice());
    let verifying_key = signing_key.verifying_key();

    let request_body = EncryptedFileRequest {
        files: encrypted_files,
        verifying_key: verifying_key.to_bytes(),
        signature: signature.to_vec(),
    };

    let response = client
        .post(url)
        .json(&request_body)
        .send()
        .await.expect("Failed to send files to the server");

    if response.status().is_success() {
        println!("Files uploaded successfully. Deleting local files...");
        // Code to delete the encrypted_files_folder
        fs::remove_dir_all(&encrypted_files_folder).expect("Failed to delete local files");
    } else {
        println!("Failed to upload files. Status: {:?}", response.status());
    }
}

async fn restore_encrypted_file_from_cloud(merkle_root_hex: String, file_index: u32) {
    let merkle_root: HashDigest = hex::decode(merkle_root_hex.clone()).expect("Failed to decode hex").try_into().expect("Invalid hash length");
    let client = Client::new();
    let url = "http://127.0.0.1:8080/get_file"; // Modify with the correct server URL

    let request_body = FileRequest {
        index: file_index as usize,
        merkle_root: merkle_root_hex.clone(),
    };

    let response = client
        .post(url)
        .json(&request_body)
        .send()
        .await.expect("Failed to request the file from the server");

    if response.status().is_success() {
        let (encrypted_file_content, merkle_proof): (Vec<u8>, MerkleProof) = response
            .json()
            .await.expect("Failed to deserialize the server response");
        let file_digest = blake2_256(&encrypted_file_content);

        assert!(
            merkle_tree::verify_proof(merkle_proof, merkle_root, file_digest),
            "Merkle proof verification failed"
        );

        // Save the file locally
        let decrypted_path = get_merkle_roots_folder_path()
            .join(merkle_root_hex)
            .join("decrypted_files");


        // Ensure the `decrypted_files` directory exists
        fs::create_dir_all(&decrypted_path).expect("Failed to create decrypted_files directory");

        let file_path = decrypted_path.join(file_index.to_string()).to_string_lossy().to_string();

        dbg!(&encrypted_file_content);
        let decryption_key = crypto::load_ed25519_private_key_and_derive_symmetric_key(get_ssh_key_path())
            .expect("Failed to derive decryption key");
        crypto::decrypt_file(encrypted_file_content, &file_path, &decryption_key)
            .expect("Failed to decrypt file");

    } else {
        println!("Failed to retrieve file. Status: {:?}", response.status());
    }
}
