use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ed25519_dalek::{Signature, Verifier};
use merkle_tree::MerkleTree;
use serde::{Deserialize, Serialize};
use sp_crypto_hashing::blake2_256;
use std::env;
use tokio_postgres::{Client, NoTls};

/// Request for storing data to be sent to the server. Contains the files, and the ed25516 verifying key, and signature.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFileRequest {
    files: Vec<Vec<u8>>,
    verifying_key: [u8; 32],
    signature: Vec<u8>,
}

/// Request for retrieving a file from the server. Contains the index of the file, and the merkle root of the files.
#[derive(Debug, Serialize, Deserialize)]
struct FileRequest {
    index: usize,
    merkle_root: String, // hex encoded hash digest ([u8; 32])
    // A signature of the hash of (index + merkle_root) signed by the verifying key used previously when uploading the files.
    signature: Vec<u8>
}

// Application state struct to share PostgreSQL client across handlers
struct AppState {
    db: Client,
}

// Function to verify signatures
fn verify_signature(verifying_key: [u8; 32], signature: Vec<u8>, message: &[u8]) -> bool {
    let signature = Signature::from_slice(&signature).expect("Invalid signature");
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&verifying_key).expect("Invalid verifying key");
    verifying_key.verify(message, &signature).is_ok()
}

// Upload endpoint to handle file uploads and store in PostgreSQL
async fn upload_files(
    data: web::Data<AppState>,
    request: web::Json<EncryptedFileRequest>,
) -> impl Responder {
    let client = &data.db;

    // File hashes are going to be used as leafs of the merkle tree
    let file_hashes: Vec<[u8; 32]> = request
        .files
        .iter()
        .map(|file| blake2_256(file.as_slice())) // Example hash function, change as needed
        .collect();
    // The combined hash is the message that was signed.
    let files_combined_hash = blake2_256(&file_hashes.concat());

    // Verify if the supplied signature is valid
    if !verify_signature(
        request.verifying_key,
        request.signature.clone(),
        &files_combined_hash,
    ) {
        return HttpResponse::Unauthorized().body("Invalid signature");
    }

    // Construct Merkle Tree
    let merkle_tree = MerkleTree::from(file_hashes);
    let merkle_root = hex::encode(merkle_tree.root());

    // Insert files into PostgreSQL. Each file is a row in the "files" table.
    // Each row contains an id, the merkle root, the file index, and the file content (encrypted by the client).
    for (index, file) in request.files.iter().enumerate() {
        let query = "INSERT INTO files (merkle_root, file_index, file_content) VALUES ($1, $2, $3)";
        if let Err(e) = client
            .execute(query, &[&merkle_root, &(index as i32), file])
            .await
        {
            eprintln!("Error inserting into database: {}", e);
            return HttpResponse::InternalServerError().body("Failed to upload files");
        }
    }

    HttpResponse::Ok().json(merkle_root)
}

// Get file endpoint to retrieve file from PostgreSQL and construct a merkle proof.
async fn get_file(data: web::Data<AppState>, request: web::Json<FileRequest>) -> impl Responder {
    let client = &data.db;

    // Query the file content
    let query = "SELECT file_content FROM files WHERE merkle_root = $1 AND file_index = $2";
    let row = match client
        .query_one(query, &[&request.merkle_root, &(request.index as i32)])
        .await
    {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Error querying database: {}", e);
            return HttpResponse::NotFound().body("File not found");
        }
    };

    let file_content: Vec<u8> = row.get(0);

    // Construct Merkle proof
    let query_all = "SELECT file_content FROM files WHERE merkle_root = $1";
    let rows = client
        .query(query_all, &[&request.merkle_root])
        .await
        .expect("Error fetching files");

    // Retrieve all files from the database that match the same merkle root
    let files: Vec<[u8; 32]> = rows
        .iter()
        .map(|row| {
            let file: Vec<u8> = row.get(0);
            blake2_256(&file)
        })
        .collect();

    // Construct the Merkle tree from the files
    let merkle_tree = MerkleTree::from(files);

    // Construct the proof
    let proof = merkle_tree
        .proof(request.index)
        .expect("Failed to generate Merkle proof");

    // Return the file content and the proof
    HttpResponse::Ok().json((file_content, proof))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Fetch database URL from environment variables (for Docker or production environments)
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
            .app_data(app_state.clone()) // Pass database connection to all handlers
            .route("/upload", web::post().to(upload_files))
            .route("/get_file", web::post().to(get_file))
    })
    .bind(("0.0.0.0", 8080))? // Bind to all network interfaces, required in Docker containers
    .run()
    .await
}
