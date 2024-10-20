use clap::{Parser, Subcommand};
use dirs::config_dir;
use ed25519_dalek::Signer;
use merkle_tree::{HashDigest, MerkleProof};
use reqwest::Client;
use serde::Serialize;
use sp_crypto_hashing::blake2_256;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;

const UPLOAD_ENDPOINT: &str = "http://127.0.0.1:8080/upload";
const DOWNLOAD_ENDPOINT: &str = "http://127.0.0.1:8080/get_file";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Shows the path to the application folder where the encrypted and decrypted files are stored, as well as the config.
    ShowAppFolder,
    /// Normally this would point to /home/user/.ssh/id_ed25519 or similar.
    /// Save the SSH key path to the configuration file. This key will be used for:
    /// - deriving a symmetric key for file encryption.
    /// - signing the files before uploading to the server.
    SetSSHKeyLocation {
        /// Path to the SSH private key
        key_path: String,
    },
    /// Read the SSH key path from the configuration file.
    ShowSSHKeyLocation,
    /// Encrypts the files with a derived key from the SSH private key, and stores the Merkle root and encrypted files
    /// Multiple calls to the same files will produce different merkle roots due to the symmetric key derivation having a nonce.
    EncryptAndMerkelizeFiles {
        /// Path to the folder containing files to encrypt
        folder_path: String,
    },
    /// Shows all the Merkle roots created by each MerkelizeFiles command
    ShowMerkleRoots,
    /// Sends the merkelized encrypted files to the cloud, and deletes them locally.
    SendToCloudAndDeleteEncryptedFiles { merkle_root: String },
    /// Restores a file by retrieving its encrypted form from the cloud, verifying the merkle proof against the merkle root, and decrypting it.
    RestoreFileFromCloud {
        merkle_root: String,
        file_index: u32,
    },
}

#[derive(Serialize)]
struct EncryptedFileRequest {
    files: Vec<Vec<u8>>,
    verifying_key: [u8; 32],
}

#[derive(Serialize)]
struct FileRequest {
    index: usize,
    merkle_root: String, // Hex-encoded hash digest ([u8; 32])
    signature: Vec<u8>,  // Signature of hash(index_bytes || merkle_root_bytes)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ShowAppFolder => {
            let mut app_path = config_dir().expect("Failed to find config directory");
            app_path.push("zama-challenge"); // Name of your application
            fs::create_dir_all(&app_path).expect("Failed to create config directory");

            println!("App folder: {}", app_path.display());
        }

        Commands::SetSSHKeyLocation { key_path } => {
            set_ssh_key_path(key_path);
        }

        Commands::ShowSSHKeyLocation => {
            println!("Saved key path: {}", get_ssh_key_path());
        }
        Commands::EncryptAndMerkelizeFiles { folder_path } => {
            encrypt_and_merkelize_files(&folder_path);
        }
        Commands::ShowMerkleRoots => {
            show_merkle_roots();
        }

        Commands::SendToCloudAndDeleteEncryptedFiles { merkle_root } => {
            send_to_cloud_and_delete_encrypted_files(merkle_root).await;
        }
        Commands::RestoreFileFromCloud {
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

fn get_ssh_key_path() -> String {
    let config_path = get_config_file_path();
    if !config_path.exists() {
        panic!("SSH key path not set. Please run set-ssh-key-location.");
    }
    fs::read_to_string(&config_path).expect("Failed to read key path")
}

fn get_config_file_path() -> PathBuf {
    let mut config_path = config_dir().expect("Failed to find config directory");
    config_path.push("zama-challenge"); // Name of your application
    fs::create_dir_all(&config_path).expect("Failed to create config directory");
    config_path.push("config.conf");
    config_path
}

fn get_merkle_roots_folder_path() -> PathBuf {
    let mut path = config_dir().expect("Failed to find config directory");
    path.push("zama-challenge");
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

    // Collect directory entries
    let mut entries: Vec<PathBuf> = fs::read_dir(folder_path)
        .expect("Failed to read directory")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();

    // Sort the entries numerically by extracting and parsing the file name
    entries.sort_by_key(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(|s| {
                // Optionally, remove file extension if present
                let s = s.split('.').next().unwrap_or(s);
                s.parse::<u32>().ok()
            })
            .unwrap_or(0)
    });

    // Encrypt the files in numerical order
    for (index, file_path) in entries.iter().enumerate() {
        let file_path_str = file_path.to_string_lossy().to_string();

        // Create an output file path with the name "0", "1", "2", etc. based on the index
        let output_file_name = format!("{}", index);
        let output_path_str = encrypted_files_folder
            .join(output_file_name)
            .to_string_lossy()
            .to_string();

        // Encrypt the file
        crypto::encrypt_file(&file_path_str, &output_path_str, &symmetric_encryption_key)
            .expect("Failed to encrypt file");
    }

    // Calculate the Merkle root of these files, and rename the folder to the Merkle root
    let merkle_tree = merkle_tree::construct_tree_from_folder_path(
        encrypted_files_folder
            .to_str()
            .expect("Failed to convert temp folder path to str"),
    );
    let merkle_root = merkle_tree.root();
    let merkle_root_hex_encoded = hex::encode(merkle_root);

    // Rename temp folder to Merkle root
    let merkle_root_folder = get_merkle_roots_folder_path().join(merkle_root_hex_encoded.clone());
    fs::rename(&temp_folder, &merkle_root_folder).expect("Failed to rename temp folder");
    println!("Merkle root: {}", merkle_root_hex_encoded);
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
    let url = UPLOAD_ENDPOINT;

    // Gather the encrypted files
    let merkle_root_folder = get_merkle_roots_folder_path().join(&merkle_root);
    let encrypted_files_folder = merkle_root_folder.join("encrypted_files");

    // Collect directory entries
    let mut entries: Vec<PathBuf> = fs::read_dir(&encrypted_files_folder)
        .expect("Failed to read directory")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();

    // Sort the entries numerically by extracting and parsing the file name
    entries.sort_by_key(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(|s| {
                // Remove file extension if present
                let s = s.split('.').next().unwrap_or(s);
                s.parse::<u32>().ok()
            })
            .unwrap_or(0)
    });

    // Read the files in numerical order
    let mut encrypted_files: Vec<Vec<u8>> = Vec::new();

    // Store them in the vec.
    for file_path in entries {
        let mut file = File::open(&file_path).expect("Failed to open file");
        let mut file_content = Vec::new();
        file.read_to_end(&mut file_content)
            .expect("Failed to read file content");
        encrypted_files.push(file_content);
    }

    // Load the ed25519 verifying key (public key)
    let verifying_key = crypto::load_ed25519_signing_key_from_path(get_ssh_key_path())
        .expect("Couldn't read the ed25519 public key file").verifying_key();

    let request_body = EncryptedFileRequest {
        files: encrypted_files,
        verifying_key: verifying_key.to_bytes(),
    };

    // Send the files to the server
    let response = client
        .post(url)
        .json(&request_body)
        .send()
        .await
        .expect("Failed to send files to the server");

    // Check if the server responded with a success status
    if response.status().is_success() {
        println!("Files uploaded successfully. Deleting local files...");
        // Delete the encrypted_files_folder
        fs::remove_dir_all(&encrypted_files_folder).expect("Failed to delete local files");
    } else {
        println!("Failed to upload files. Status: {:?}", response.status());
    }
}

async fn restore_encrypted_file_from_cloud(merkle_root_hex: String, file_index: u32) {
    // Convert the hex-encoded merkle root to a HashDigest ([u8; 32])
    let merkle_root: HashDigest = hex::decode(&merkle_root_hex)
        .expect("Failed to decode hex")
        .try_into()
        .expect("Invalid hash length");
    let client = Client::new();
    let url = DOWNLOAD_ENDPOINT;

    // Load the ed25519 signing key
    let signing_key = crypto::load_ed25519_signing_key_from_path(get_ssh_key_path())
        .expect("Couldn't read the ed25519 private key file");

    // Construct the message to sign: hash(index_bytes || merkle_root_bytes)
    let index_bytes = (file_index as u32).to_be_bytes();
    let merkle_root_bytes = hex::decode(&merkle_root_hex).expect("Failed to decode merkle root");

    let mut message_data = Vec::new();
    message_data.extend_from_slice(&index_bytes);
    message_data.extend_from_slice(&merkle_root_bytes);

    // Compute the hash of the concatenated data
    let message_hash = blake2_256(&message_data);

    // Sign the message hash
    let signature = signing_key.sign(&message_hash);

    let request_body = FileRequest {
        index: file_index as usize,
        merkle_root: merkle_root_hex.clone(),
        signature: signature.to_bytes().to_vec(),
    };

    // Send the request to the server
    let response = client
        .post(url)
        .json(&request_body)
        .send()
        .await
        .expect("Failed to request the file from the server");

    if response.status().is_success() {
        // Server responds with the stored encrypted file, and a merkle proof
        let (encrypted_file_content, merkle_proof): (Vec<u8>, MerkleProof) = response
            .json()
            .await
            .expect("Failed to deserialize the server response");

        // The merkle leaf to verify against is the hash of the encrypted file content
        let file_digest = blake2_256(&encrypted_file_content);

        // Verify the merkle proof.
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

        // The file name is the index that was requested to the server
        let file_path = decrypted_path
            .join(file_index.to_string())
            .to_string_lossy()
            .to_string();

        // Load the decryption symmetric key derived from the SSH private key
        let decryption_key =
            crypto::load_ed25519_private_key_and_derive_symmetric_key(get_ssh_key_path())
                .expect("Failed to derive decryption key");

        // Decrypt the file and write it to the output path
        crypto::decrypt_file(encrypted_file_content, &file_path, &decryption_key)
            .expect("Failed to decrypt file");

        println!("File restored successfully to {}", file_path);
    } else {
        println!("Failed to retrieve file. Status: {:?}", response.status());
    }
}
