# Transponder Justfile
# Run `just --list` to see all available commands

# Default recipe: list all commands
default:
    @just --list

# Build the project
build:
    cargo build

# Build with optional Tor relay support
build-tor:
    cargo build --features tor

# Build release binary
build-release:
    cargo build --release

# Build release binary with optional Tor relay support
build-release-tor:
    cargo build --release --features tor

# Run the server with default config
run:
    cargo run -- --config config/default.toml

# Run the server with Tor relay support enabled
run-tor:
    cargo run --features tor -- --config config/default.toml

# Run the server with local config (for development)
run-local:
    cargo run -- --config config/local.toml

# Run the server with debug logging
run-debug:
    TRANSPONDER_LOGGING_LEVEL=debug TRANSPONDER_LOGGING_FORMAT=pretty cargo run -- --config config/local.toml

# Run all tests
test:
    cargo test

# Run all tests with Tor relay support enabled
test-tor:
    cargo test --features tor

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Run tests for a specific module
test-module module:
    cargo test {{module}}::

# Check code without building
check:
    cargo check

# Check code with Tor relay support enabled
check-tor:
    cargo check --features tor

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Run dependency vulnerability audit
audit:
    ./scripts/cargo-audit.sh

# Run the raw dependency vulnerability audit without policy ignores
audit-strict:
    cargo audit

# Format code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt -- --check

# Run all checks (format, lint, test, audit)
ci: fmt-check lint test audit

# Clean build artifacts
clean:
    cargo clean

# Clean coverage artifacts
clean-coverage:
    rm -rf target/coverage target/llvm-cov-target

# Run test coverage using LLVM (requires cargo-llvm-cov)
coverage:
    cargo llvm-cov --html

# Run test coverage and output to stdout
coverage-text:
    cargo llvm-cov

# Run test coverage with detailed report
coverage-report:
    cargo llvm-cov report --html --open

# Install development dependencies
install-dev-deps:
    cargo install cargo-audit
    cargo install cargo-llvm-cov
    rustup component add llvm-tools-preview

# Watch for changes and run tests
watch-test:
    cargo watch -x test

# Watch for changes and run checks
watch-check:
    cargo watch -x check

# Generate documentation
doc:
    cargo doc --no-deps

# Generate and open documentation
doc-open:
    cargo doc --no-deps --open
