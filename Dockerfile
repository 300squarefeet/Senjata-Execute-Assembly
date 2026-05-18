FROM rust:1.85-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git binutils file build-essential ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly-2025-01-25 \
        --component rust-src --component clippy && \
    rustup target add x86_64-pc-windows-gnu --toolchain nightly-2025-01-25

RUN cargo install cargo-make
RUN cargo install --git https://github.com/MEhrn00/boflink boflink

WORKDIR /work
ENTRYPOINT ["cargo", "make"]
CMD ["build"]
