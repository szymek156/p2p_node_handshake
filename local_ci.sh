echo "Format"
cargo fmt --all

echo "Clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "Test"
RUST_LOG=info cargo test -- --nocapture --include-ignored

