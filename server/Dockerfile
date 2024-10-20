# Start from the official Rust image as the build stage
FROM rust:latest as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the source code
COPY . .

# Build the release version of the server binary
RUN cargo build --release

# Start a new stage with a smaller image
FROM debian:stable

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/server .

# Expose the port the app will run on
EXPOSE 8080

# Run the application
CMD ["./server"]
