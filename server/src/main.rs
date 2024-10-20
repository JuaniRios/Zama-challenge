use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use ed25519_dalek::{Signature, Verifier};
use merkle_tree::{HashDigest, MerkleProof, MerkleTree}; // Assuming you have a Merkle tree implementation
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sp_crypto_hashing::blake2_256;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFileRequest {
    files: Vec<Vec<u8>>,
    verifying_key: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileRequest {
    index: usize,
    merkle_root: String, // hex encoded hash digest ([u8; 32])
}
struct AppState {
    conn: Mutex<Connection>, // SQLite connection
}

fn verify_signature(verifying_key: [u8; 32], signature: Vec<u8>, message: &[u8]) -> bool {
    let signature = Signature::from_slice(signature.as_slice()).expect("Invalid signature");
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&verifying_key)
        .expect("Invalid verifying key");
    verifying_key.verify(message, &signature).is_ok()
}

#[post("/upload")]
async fn upload_files(
    data: web::Data<AppState>,
    request: web::Json<EncryptedFileRequest>,
) -> impl Responder {
    let conn = data.conn.lock().unwrap();

    // Verify the signature
    let file_hashes: Vec<[u8; 32]> = request
        .files
        .iter()
        .map(|file| blake2_256(file.as_slice())) // Example hash function, change as needed
        .collect();
    let files_combined_hash = blake2_256(&file_hashes.concat());

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

    // Store Merkle tree and files in SQLite
    for (index, file) in request.files.iter().enumerate() {
        conn.execute(
            "INSERT INTO files (merkle_root, file_index, file_content) VALUES (?1, ?2, ?3)",
            params![merkle_root, index, file],
        )
        .unwrap();
    }

    HttpResponse::Ok().json(merkle_root)
}

#[post("/get_file")]
async fn get_file(data: web::Data<AppState>, request: web::Json<FileRequest>) -> impl Responder {
    let conn = data.conn.lock().unwrap();
    debug_print_all_rows(&conn);
    // Query the file from the database
    let mut stmt = conn
        .prepare("SELECT file_content FROM files WHERE merkle_root = ?1 AND file_index = ?2")
        .unwrap();
    let file_content: Vec<u8> = stmt
        .query_row(params![request.merkle_root, request.index], |row| {
            row.get(0)
        })
        .expect("Row not found");

    // Construct Merkle proof
    let mut stmt = conn
        .prepare("SELECT file_content FROM files WHERE merkle_root = ?1")
        .unwrap();
    let files: Vec<[u8; 32]> = stmt
        .query_map(params![request.merkle_root], |row| {
            let file: Vec<u8> = row.get(0)?;
            Ok(blake2_256(file.as_slice()))
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();

    let merkle_tree = MerkleTree::from(files);
    let proof = merkle_tree
        .proof(request.index)
        .expect("Proof generation failed");

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
            file_content BLOB NOT NULL
        )",
        [],
    )
    .unwrap();

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

fn debug_print_all_rows(conn: &rusqlite::Connection) {
    let mut stmt = conn.prepare("SELECT id, merkle_root, file_index, file_content FROM files").expect("Failed to prepare debug statement");

    let rows = stmt
        .query_map([], |row| {
            let id: i32 = row.get(0)?;
            let merkle_root: String = row.get(1)?;
            let file_index: i32 = row.get(2)?;
            let file_content: Vec<u8> = row.get(3)?; // Assuming file_content is stored as BLOB

            Ok((id, merkle_root, file_index, file_content))
        })
        .expect("Failed to execute debug query");

    for row in rows {
        let (id, merkle_root, file_index, file_content) = row.expect("Failed to get row data");
        println!("ID: {}, Merkle Root: {}, File Index: {}, File Content (hex): {}",
                 id,
                 merkle_root,
                 file_index,
                 hex::encode(file_content)); // Display file content as a hex string
    }
}