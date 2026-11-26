# Instructions for AI assistants

MiraServe is a web server written in Rust. This file is for AI assistants that open this repository.

## If you are helping someone install or run MiraServe

Read and follow [`skills/miraserve-setup/SKILL.md`](skills/miraserve-setup/SKILL.md). It contains the tested
steps for installing, configuring static sites, reverse proxying, PHP, certificates, reloads and
migration, with the real error messages. The same guide is published at
<https://miraserve.org/ai-setup.txt>, and the documentation index for machines is
<https://miraserve.org/llms.txt>.

The short version of its rules:

- The configuration is KDL. Do not write Nginx or Apache syntax, and do not invent directives.
- Run `miraserve check --fs --strict <file>` before every start or reload.
- Never switch off the sandbox, TLS settings or security headers to make an error go away.
- `.htaccess` files are not read.
- Do not cut over a live site without testing each host name first and asking the user.

## If you are working on the code

- Build: `cargo build --release --locked --bin miraserve` (Rust 1.95 or newer).
- Before proposing a change, run what the project runs:

  ```sh
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-targets --locked
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
  cargo deny check
  ```

- Every crate that ships in the binary has `#![forbid(unsafe_code)]` and denies `unwrap`, `expect` and
  `panic!`. Do not add `unsafe`, and do not add dependencies without saying why.
- `vendor/h2` is a patched copy of the `h2` crate with provenance checks (`vendor/README.md`,
  `scripts/verify-vendor-h2.sh`). Do not edit it by hand.
- Behaviour is specified in `docs/SPEC.md` and operations in `docs/DEPLOYMENT.md`. A change that alters
  what an existing configuration does is a behaviour change and must be stated as one.
- Security problems are reported privately (see `SECURITY.md`), not in public issues or pull requests.

## What not to claim

MiraServe is pre-1.0. Its downloads are unsigned. It has not been audited by an outside security firm.
The sandbox (Landlock and seccomp) exists on Linux only. Do not describe it as faster than another
server; this project publishes no comparisons.
