use actix_web::{web, App, HttpResponse, HttpServer, Responder, post};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use merkle_tree::{MerkleTree, MerkleProof}; // Assuming you have a Merkle tree implementation
use sha2::Sha256;
use sp_crypto_hashing::blake2_256;

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFileRequest {
    files: Vec<Vec<u8>>, // Encrypted file bytes
    public_key: String, // Hex encoded Ed25519 public key
    signature: String,  // Hex encoded signature over the hash of files
}

#[derive(Debug, Serialize, Deserialize)]
struct FileRequest {
    index: usize,
    merkle_root: String,
}

struct AppState {
    conn: Mutex<Connection>, // SQLite connection
}

fn verify_signature(public_key: &str, signature: &str, message: &[u8]) -> bool {
    let public_key_bytes = hex::decode(public_key).expect("Invalid public key");
    let public_key = PublicKey::from_bytes(&public_key_bytes).expect("Failed to parse public key");

    let signature_bytes = hex::decode(signature).expect("Invalid signature");
    let signature = Signature::from_bytes(&signature_bytes).expect("Failed to parse signature");

    public_key.verify(message, &signature).is_ok()
}

#[post("/upload")]
async fn upload_files(data: web::Data<AppState>, request: web::Json<EncryptedFileRequest>) -> impl Responder {
    let conn = data.conn.lock().unwrap();

    // Verify the signature
    let file_hashes: Vec<[u8; 32]> = request
        .files
        .iter()
        .map(|file| blake2_256(file.as_slice())) // Example hash function, change as needed
        .collect();
    let files_combined_hash = blake2_256(&file_hashes.concat());

    if !verify_signature(&request.public_key, &request.signature, &files_combined_hash) {
        return HttpResponse::Unauthorized().body("Invalid signature");
    }

    // Construct Merkle Tree
    let merkle_tree = MerkleTree::from(file_hashes);
    let merkle_root = hex::encode(merkle_tree.root());

    // Store Merkle tree and files in SQLite
    for (index, file) in request.files.iter().enumerate() {
        conn.execute(
            "INSERT INTO files (merkle_root, file_index, file_content) VALUES (?1, ?2, ?3)",
            params![merkle_root, index, file],
        ).unwrap();
    }

    HttpResponse::Ok().json(merkle_root)
}

#[post("/get_file")]
async fn get_file(data: web::Data<AppState>, request: web::Json<FileRequest>) -> impl Responder {
    let conn = data.conn.lock().unwrap();

    // Query the file from the database
    let mut stmt = conn.prepare("SELECT file_content FROM files WHERE merkle_root = ?1 AND file_index = ?2").unwrap();
    let file_content: String = stmt.query_row(params![request.merkle_root, request.index], |row| row.get(0)).unwrap();

    // Construct Merkle proof
    let mut stmt = conn.prepare("SELECT file_content FROM files WHERE merkle_root = ?1").unwrap();
    let files: Vec<[u8; 32]> = stmt
        .query_map(params![request.merkle_root], |row| {
            let file: String = row.get(0)?;
            Ok(blake2_256(file.as_bytes()))
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();

    let merkle_tree = MerkleTree::from(files);
    let proof = merkle_tree.proof(request.index).expect("Proof generation failed");

    HttpResponse::Ok().json((file_content, proof))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let conn = Connection::open("files.db").unwrap();

    // Create a table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            merkle_root TEXT NOT NULL,
            file_index INTEGER NOT NULL,
            file_content TEXT NOT NULL
        )",
        [],
    ).unwrap();

    let app_state = web::Data::new(AppState {
        conn: Mutex::new(conn),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(upload_files)
            .service(get_file)
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
