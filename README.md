# ZAMA Challenge
## Challenge Description
Imagine a client has a large set of potentially small files {F0, F1, …, Fn} and wants to upload them to a server and then delete its local copies. The client wants, however, to later download an arbitrary file from the server and be convinced that the file is correct and is not corrupted in any way (in transport, tampered with by the server, etc.).

You should implement the client, the server and a Merkle tree to support the above (we expect you to implement the Merkle tree rather than use a library, but you are free to use a library for the underlying hash functions).

The client must compute a single Merkle tree root hash and keep it on its disk after uploading the files to the server and deleting its local copies. The client can request the i-th file Fi and a Merkle proof Pi for it from the server. The client uses the proof and compares the resulting root hash with the one it persisted before deleting the files - if they match, file is correct.

You can use any programming language you want (we use Go and Rust internally). We would like to see a solution with networking that can be deployed across multiple machines, and as close to production-ready as you have time for. Please describe the short-coming your solution have in a report, and how you would improve on them given more time.

## Approach
My approach to the problem consisted of the client interacting with a CLI locally, and the server being a docker container which interacts with a PostgreSQL outside it. 
This would allow later on to create clusters of servers all accessible from a single endpoint, and sharing the same data.

After everything is setup, the flow is as follows:
1) The user stores all of their files in a single folder. He should rename the files to u32 numbers. This is because before constructing the Merkle tree, we need to sort the files based on something, so I chose a u32. 
2) The user calls the CLI with `set-ssh-key-location {path}`. Since most devs already have an ssh ed25519 key stored in their computer, its the least setup to just use that for encrypting the files (doing a symmetric key derivation), and also to sign the files when sending them to the server.
3) The user calls the CLI with `encrypt-and-merkelize-files {path}`. For path, we use the one from step 1. This command will:
    -  Create a Symmetric encryption key from the SSH key.
    -  Encrypt all files and store them in a CLI-defined folder.
    -  Calculate the Merkle root of these files
    -  Rename the folder where the encrypted files are stored to the merkle root
    -  Outputs the hex encoded merkle root to the CLI
4) The user calls the CLI with `send-to-cloud-and-delete-encrypted-files {merkle_root}`.
This command reads all the files under the folder named {merkle_root}, sends the files along with the ed25519 public key
The server will receive the files, construct the merkle tree from the files. and then store in the database each file, with its Merkle root and public key.
5) At some point in the future, if the user wants to retrieve the file at index 9, which would correspond to the 10th file assuming he named his files starting with 0, he calls the CLI with `restore-file-from-cloud {merkle_root} {index}`
The CLI will send the server the merkle_root, index, and a signature over the hash of both, so the server knows the requester owns the data. The CLI then receives the encrypted file and a Merkle proof. If the proof is valid, it will then decrypt the file, and store it under the path shown in the CLI response.

## Future optimizations
- The linking of files to a public key can be done in a separate table by using the merkle root as the main key.
- I use a lot of expect which will break the server and client. System needs better error handling
- Not enough tests. I didn't have time for comprehensive testing. I tested mainly by doing the flow described above. But there are many edge cases not considered which will break the client and server.
- Container orquestration. I would have liked to add Kubernetes, load balancers, etc to make the app scalable, but again not enough time.

## Full Setup
This setup assumes you are using a Mac with Apple Silicon.
1) Add a .env file inside the server folder with the following:
```
POSTGRES_USER=zama_server
POSTGRES_PASSWORD=zama_password
POSTGRES_DB=zama_challenge
POSTGRES_HOST=host.docker.internal
POSTGRES_PORT=5432
```

2) Install PostgreSQL, Docker, and Rust
   
3) Run the following psql commands:
```
CREATE DATABASE zama_challenge;
CREATE USER zama_user WITH PASSWORD 'zama_password';
GRANT ALL PRIVILEGES ON DATABASE zama_challenge TO zama_user;
GRANT CONNECT ON DATABASE your_database TO zama_server;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO zama_server;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO zama_server;
CREATE TABLE files ( id SERIAL PRIMARY KEY, merkle_root TEXT NOT NULL, file_index INTEGER NOT NULL, file_content BYTEA NOT NULL );
```
You can choose a different username, password, and table name. but make sure to reflect them in the .env.

4) `Run cargo build --release` This will let us use the client CLI. The server is using docker.
   
5) Start docker
   
6) cd into the server folder, and run `docker-compose up --build`. This will start the server container.
   
7) create a new folder somewhere, and create multiple small files with names from 0..n.
You can run the following Python script inside the folder:
```
for i in range(0, 50):
    filename = f"{i}"
    with open(filename, 'w') as f:
        f.write(f"This is file number {i}")
```

8) Now we start interfacing with the client binary. cd into this repo's root.
Now Add the path to your ssh key to the client CLI. Example command:
```
./target/release/client set-ssh-key-location "/Users/juanrios/.ssh/id_ed25519"
```

9) Encrypt and Merkelize the files with for example:
```
./target/release/client encrypt-and-merkelize-files ~/Desktop/test-files`
```
This is assuming the files were generated in `~/Desktop/test-files`

10) Save the merkle root shown in the CLI.

11) Send the files to the cloud with for example:
```
./target/release/client send-to-cloud-and-delete-encrypted-files 609b9807bffb5df3094f55ba6db769795adcfa47a60f1c0f0c50e4f032e4cd34
```
where the last part is the merkle root.

12) Retrieve file at index 42, by calling for example:
```
./target/release/client restore-file-from-cloud 609b9807bffb5df3094f55ba6db769795adcfa47a60f1c0f0c50e4f032e4cd34 42
```

13) Copy the path shown by the cli to the restored file, and open it with for example:
```
vi "/Users/juanrios/Library/Application Support/zama-challenge/merkle_roots/609b9807bffb5df3094f55ba6db769795adcfa47a60f1c0f0c50e4f032e4cd34/decrypted_files/42"
```
