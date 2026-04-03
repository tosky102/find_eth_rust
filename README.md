# addr_finder

A high-performance Rust tool that checks whether randomly generated private keys produce addresses that match a given list. Uses multi-core parallelism for maximum throughput.

## How It Works

1. Loads a list of addresses from `data/addresses.json`
2. Spawns worker threads (one per CPU core minus one)
3. Each worker continuously generates random keys, derives the corresponding address, and checks if it exists in the target set
4. On first match, writes the result to `data/v.json` and exits

## Requirements

- Rust 1.70+ (install via [rustup](https://rustup.rs/))

## Build

```bash
cargo build --release
```

## Usage

### Default mode (20-byte hex addresses)

1. Place your target addresses in `data/addresses.json` (see format below)
2. Run:

```bash
cargo run --release
```

Results are written to `data/v.json`.

### XRP mode (`--xrp`)

1. Place your target addresses in `data/addresses_x.json` (classic `r...` or hex)
2. Run:

```bash
cargo run --release -- --xrp
```

Results are written to `data/v_x.json`.

Or run the release binary directly:

```bash
./target/release/addr_finder
./target/release/addr_finder --xrp
```

## Input Format (`data/addresses.json`)

A JSON array of 20-byte hex addresses. Two formats are supported:

```json
[
  "0x00000000219ab540356cBB839Cbe05303d7705Fa",
  "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
]
```

Or with objects:

```json
[
  { "address": "0x00000000219ab540356cBB839Cbe05303d7705Fa" }
]
```

Addresses may include or omit the `0x` prefix; checksum is case-insensitive.

### Input format for XRP (`data/addresses_x.json`)

Classic addresses (starts with `r`) or 40-char hex:

```json
[
  "rN7n7otQDd6FczFgLdlqtyMVrn3e1Djxv7",
  "rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY"
]
```

## Output (`data/v.json` and `data/v_x.json`)

When a match is found, the result is written as:

```json
{
  "address": "0x...",
  "private_key": "0x..."
}
```

## Performance

- Uses all available CPU cores (minus one)
- Progress is logged every 10 million checks per worker
- No allocations in the hot path for address derivation and lookup

## Note

Finding a collision against a large, arbitrary address set is astronomically improbable. This tool is intended for testing or vanity address generation against known patterns.
