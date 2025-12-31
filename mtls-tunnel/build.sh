#!/bin/bash
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
