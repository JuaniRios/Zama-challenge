use hkdf::Hkdf;
use sha2::Sha256;
use sodiumoxide::crypto::secretbox;
use ssh_keys::openssh::parse_private_key;
use ssh_keys::PrivateKey;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Loads the Ed25519 private key from the specified SSH key file and derives a symmetric key from it.
///
/// # Arguments
///
/// * `ssh_key_path` - The file path to the SSH private key.
///
/// # Returns
///
/// * `Result<Key, Box<dyn Error>>` - The derived symmetric key or an error.
///
/// # Errors
///
/// This function will return an error if:
/// - The key file cannot be read.
/// - The key is not an Ed25519 key.
/// - The key cannot be parsed.
/// - The symmetric key derivation fails.
pub fn load_ed25519_private_key_and_derive_symmetric_key(
    ssh_key_path: String,
) -> Result<secretbox::Key, Box<dyn Error>> {
    // Read the SSH private key file
    let ssh_key_path = Path::new(&ssh_key_path);
    let key_content_bytes = fs::read(ssh_key_path)?;
    let key_content_str = String::from_utf8_lossy(&key_content_bytes);

    // Parse the SSH private key (supports OpenSSH format)
    let ssh_private_key = parse_private_key(&key_content_str)?
        .first()
        .ok_or("No key found")?
        .to_owned();

    // Extract the key bytes
    let key_bytes = match ssh_private_key {
        PrivateKey::Rsa { .. } => return Err("Only Ed25519 keys are supported".into()),
        PrivateKey::Ed25519(bytes) => bytes,
    };

    // Derive a symmetric key using HKDF with SHA-256
    let hk = Hkdf::<Sha256>::new(None, key_bytes.as_slice());

    // Prepare output key material buffer
    let mut okm = [0u8; 32]; // 32 bytes for a 256-bit key

    // Use a context string for the HKDF expand step
    hk.expand(b"file encryption key", &mut okm)
        .map_err(|_| "Failed to apply HKDF-Expand operation")?;

    // Create a sodiumoxide secretbox::Key from the derived bytes
    let symmetric_key = secretbox::Key::from_slice(&okm).ok_or("Failed to create symmetric key")?;

    Ok(symmetric_key)
}

/// Encrypts a file using the provided symmetric key.
///
/// # Arguments
///
/// * `input_path` - Path to the input file to encrypt.
/// * `output_path` - Path where the encrypted file will be saved.
/// * `key` - Symmetric key for encryption.
///
/// # Errors
///
/// Returns an error if file operations fail or encryption fails.
pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    key: &secretbox::Key,
) -> Result<(), Box<dyn Error>> {
    // Read the file contents into a buffer
    let mut file = File::open(input_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Generate a nonce
    let nonce = secretbox::gen_nonce();

    // Encrypt the file content
    let ciphertext = secretbox::seal(&buffer, &nonce, key);

    // Write the nonce and ciphertext to the output file
    let mut output = File::create(output_path)?;
    output.write_all(nonce.as_ref())?;
    output.write_all(&ciphertext)?;

    Ok(())
}

/// Decrypts a file using the provided symmetric key.
///
/// # Arguments
///
/// * `input_path` - Path to the encrypted input file.
/// * `output_path` - Path where the decrypted file will be saved.
/// * `key` - Symmetric key for decryption.
///
/// # Errors
///
/// Returns an error if file operations fail or decryption fails.
pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    key: &secretbox::Key,
) -> Result<(), Box<dyn Error>> {
    // Read the encrypted file contents into a buffer
    let mut file = File::open(input_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Ensure the buffer is at least as long as the nonce
    if buffer.len() < secretbox::NONCEBYTES {
        return Err("Encrypted file is too short.".into());
    }

    // Extract the nonce and ciphertext
    let (nonce_bytes, ciphertext) = buffer.split_at(secretbox::NONCEBYTES);
    let nonce = secretbox::Nonce::from_slice(nonce_bytes).ok_or("Failed to read nonce")?;

    // Decrypt the file content
    let plaintext = secretbox::open(ciphertext, &nonce, key).map_err(|_| "Decryption failed")?;

    // Write the plaintext to the output file
    let mut output = File::create(output_path)?;
    output.write_all(&plaintext)?;

    Ok(())
}

#[test]
fn test_encryption_decryption_flow() -> Result<(), Box<dyn Error>> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| "Failed to initiate sodiumoxide")?;

    // Make sure this path points to your Ed25519 private key file
    let key_path = Path::new("/Users/juanrios/.ssh/id_ed25519");

    // Load the symmetric key from the private key
    let symmetric_key = load_ed25519_private_key_and_derive_symmetric_key(key_path)?;

    // Sample data to encrypt
    let original_data = b"Hello, this is a test message!";

    // Create a temporary directory to store test files
    let dir = tempfile::tempdir()?;

    // Paths for input, encrypted, and decrypted files
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.bin");
    let decrypted_path = dir.path().join("decrypted.txt");

    // Write the original data to the input file
    {
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(original_data)?;
    }

    // Encrypt the file
    encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        &symmetric_key,
    )?;

    // Decrypt the file
    decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        &symmetric_key,
    )?;

    // Read the decrypted data
    let mut decrypted_data = Vec::new();
    {
        let mut decrypted_file = File::open(&decrypted_path)?;
        decrypted_file.read_to_end(&mut decrypted_data)?;
    }

    // Assert that the decrypted data matches the original data
    assert_eq!(original_data.to_vec(), decrypted_data);

    // Clean up the temporary directory
    dir.close()?;

    Ok(())
}
