use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ed25519_dalek::{Signature, Verifier};
use merkle_tree::MerkleTree;
use serde::{Deserialize, Serialize};
use sp_crypto_hashing::blake2_256;
use std::env;
use tokio_postgres::{Client, NoTls};

/// Request for storing data to be sent to the server.
/// Contains the files and the ed25519 verifying key.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFileRequest {
    files: Vec<Vec<u8>>,
    verifying_key: [u8; 32],
}

/// Request for retrieving a file from the server.
/// Contains the index of the file, the merkle root of the files,
/// and a signature of the hash of (index + merkle_root) signed by the verifying key.
#[derive(Debug, Serialize, Deserialize)]
struct FileRequest {
    index: usize,
    merkle_root: String, // Hex-encoded hash digest ([u8; 32])
    signature: Vec<u8>,  // Signature of hash(index_bytes || merkle_root_bytes)
}

// Application state struct to share PostgreSQL client across handlers
struct AppState {
    db: Client,
}

// Function to verify signatures
fn verify_signature(verifying_key: &[u8; 32], signature: &[u8], message: &[u8]) -> bool {
    let signature = match Signature::from_slice(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(verifying_key) {
        Ok(key) => key,
        Err(_) => return false,
    };
    verifying_key.verify(message, &signature).is_ok()
}

// Upload endpoint to handle file uploads and store in PostgreSQL
async fn upload_files(
    data: web::Data<AppState>,
    request: web::Json<EncryptedFileRequest>,
) -> impl Responder {
    let client = &data.db;

    // File hashes are going to be used as leaves of the Merkle tree
    let file_hashes: Vec<[u8; 32]> = request
        .files
        .iter()
        .map(|file| blake2_256(file))
        .collect();

    // Construct Merkle Tree
    let merkle_tree = MerkleTree::from(file_hashes.clone());
    let merkle_root = merkle_tree.root();
    let merkle_root_hex = hex::encode(merkle_root);

    // Insert files into PostgreSQL
    for (index, file) in request.files.iter().enumerate() {
        let query = "INSERT INTO files (merkle_root, file_index, file_content, verifying_key) VALUES ($1, $2, $3, $4)";
        if let Err(e) = client
            .execute(
                query,
                &[&merkle_root_hex, &(index as i32), file, &request.verifying_key.to_vec()],
            )
            .await
        {
            eprintln!("Error inserting into database: {}", e);
            return HttpResponse::InternalServerError().body("Failed to upload files");
        }
    }

    HttpResponse::Ok().json(merkle_root_hex)
}

// Get file endpoint to retrieve file from PostgreSQL and construct a Merkle proof
async fn get_file(data: web::Data<AppState>, request: web::Json<FileRequest>) -> impl Responder {
    let client = &data.db;

    // Query the file content and verifying key
    let query =
        "SELECT file_content, verifying_key FROM files WHERE merkle_root = $1 AND file_index = $2";
    let row = match client
        .query_one(query, &[&request.merkle_root, &(request.index as i32)])
        .await
    {
        Ok(row) => row,
        Err(_) => return HttpResponse::NotFound().body("File not found"),
    };

    let file_content: Vec<u8> = row.get(0);
    let verifying_key: Vec<u8> = row.get(1);
    let verifying_key: [u8; 32] = verifying_key.as_slice().try_into().expect("Invalid key size");

    // Construct the message: hash(index_bytes || merkle_root_bytes)
    let index_bytes = (request.index as u32).to_be_bytes();
    let merkle_root_bytes = match hex::decode(&request.merkle_root) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().body("Invalid merkle_root format"),
    };

    let mut message_data = Vec::new();
    message_data.extend_from_slice(&index_bytes);
    message_data.extend_from_slice(&merkle_root_bytes);

    // Compute the hash of the concatenated data
    let message_hash = blake2_256(&message_data);

    // Verify the signature
    if !verify_signature(&verifying_key, &request.signature, &message_hash) {
        return HttpResponse::Unauthorized().body("Invalid signature");
    }

    // Fetch all file contents with the same merkle root
    let query_all =
        "SELECT file_content FROM files WHERE merkle_root = $1 ORDER BY file_index ASC";
    let rows = match client.query(query_all, &[&request.merkle_root]).await {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Error querying database: {}", e);
            return HttpResponse::InternalServerError().body("Failed to fetch files");
        }
    };

    // Retrieve all files and compute their hashes
    let files: Vec<[u8; 32]> = rows
        .iter()
        .map(|row| {
            let file: Vec<u8> = row.get(0);
            blake2_256(&file)
        })
        .collect();

    // Reconstruct the Merkle tree
    let merkle_tree = MerkleTree::from(files);

    // Generate the Merkle proof for the requested index
    let proof = merkle_tree.proof(request.index).expect("Failed to generate proof");

    // Return the file content and the proof
    HttpResponse::Ok().json((file_content, proof))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Fetch database URL from environment variables
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Connect to PostgreSQL
    let (client, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Spawn the connection manager
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Prepare application state
    let app_state = web::Data::new(AppState { db: client });

    // Create Actix Web server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/upload", web::post().to(upload_files))
            .route("/get_file", web::post().to(get_file))
    })
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
