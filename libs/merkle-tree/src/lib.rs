use std::fs;
use std::path::PathBuf;
// We use Blake2b instead of Sha2 since its around 2x faster with the same security level.
// I also considered using TwoX since it's even faster than Blake2b, but it's not cryptographically secure.
use sp_crypto_hashing::blake2_256;

#[test]
fn root_works() {
    let hashed_files = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let tree = MerkleTree::from(hashed_files.clone());
    dbg!(tree.nodes.clone());

    let first_file = hashed_files[0];
    let second_file = hashed_files[1];
    let combined = [first_file, second_file].concat();
    let first_hash = blake2_256(&combined);

    let second_hash = [3u8; 32];

    let combined = [first_hash, second_hash].concat();
    let root_hash = blake2_256(&combined);

    assert_eq!(tree.root(), root_hash);
}

#[test]
fn proof_works() {
    let hashed_files = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let tree = MerkleTree::from(hashed_files.clone());
    let proof = tree.proof(1).unwrap();
    let root = tree.root();
    let file = hashed_files[1];

    assert!(verify_proof(proof, root, file));
}

pub type HashDigest = [u8; 32];
pub type MerkleProof = Vec<(HashDigest, bool)>;

pub struct MerkleTree {
    nodes: Vec<Vec<HashDigest>>,
}
impl From<Vec<HashDigest>> for MerkleTree {
    fn from(hashed_files: Vec<HashDigest>) -> Self {
        // Knowing the tree depth, we can access the leaf layer at index 0, the root layer at index `tree_depth`, and the required intermediary nodes at the other indices.
        let tree_depth = (hashed_files.len() as f64).log2().ceil() as usize;
        // Leaf nodes are the hashed files. We start by filling the leaf nodes with empty leaves and then we fill the ones that have files.
        let leaf_nodes = hashed_files;

        // once current_depth == tree_depth, we have the root node
        let mut current_depth = 0usize;
        let mut nodes = vec![leaf_nodes];
        while current_depth < tree_depth {
            let previous_layer_nodes = nodes[current_depth].chunks(2);
            let mut new_layer_nodes = Vec::new();
            for chunk in previous_layer_nodes {
                match chunk {
                    [left_node, right_node] => {
                        let left_node = *left_node;
                        let right_node = *right_node;
                        let combined = [left_node, right_node].concat();
                        new_layer_nodes.push(blake2_256(&combined));
                    }
                    [left_node] => {
                        new_layer_nodes.push(*left_node);
                    }
                    _ => unreachable!(),
                }
            }
            current_depth += 1;
            nodes.push(new_layer_nodes);
        }

        MerkleTree { nodes }
    }
}

impl MerkleTree {
    pub fn root(&self) -> HashDigest {
        *self.nodes.last().unwrap().first().unwrap()
    }
    pub fn proof(&self, file_index: usize) -> Result<Vec<(HashDigest, bool)>, &str> {
        if file_index > self.nodes[0].len() - 1 {
            return Err("File index out of bounds");
        }

        let mut proof = Vec::new();
        let mut current_index = file_index;
        for layer in &self.nodes {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if let Some(sibling_node) = layer.get(sibling_index) {
                let is_left = sibling_index < current_index;
                proof.push((*sibling_node, is_left));
            }
            current_index /= 2;
        }
        Ok(proof)
    }
}

pub fn verify_proof(proof: MerkleProof, root: HashDigest, file: HashDigest) -> bool {
    let mut current_node = file;
    for (sibling_node, is_left) in proof {
        if is_left {
            let combined = [sibling_node, current_node].concat();
            current_node = blake2_256(&combined);
        } else {
            let combined = [current_node, sibling_node].concat();
            current_node = blake2_256(&combined);
        }
    }
    current_node == root
}

// Reads all the files in a folder, hashes them, and constructs a Merkle tree from the hashes.
pub fn construct_tree_from_folder_path(folder_path: &str) -> MerkleTree {
    // Collect directory entries into a vector
    let mut entries: Vec<PathBuf> = fs::read_dir(folder_path)
        .expect("Failed to read directory")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();

    // Sort the entries numerically by extracting and parsing the file names
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

    // Read and hash the files in the sorted order
    let hashed_files: Vec<HashDigest> = entries
        .iter()
        .map(|file_path| {
            let file_content = fs::read(file_path).expect("Failed to read file");
            blake2_256(&file_content)
        })
        .collect();

    MerkleTree::from(hashed_files)
}
