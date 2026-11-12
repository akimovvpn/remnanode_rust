# Remnanode Rust Implementation Plan

**Goal:** Rust panel-compatible Remnanode and tested automatic upstream update PRs.
**Architecture:** axum mutual TLS frontend, serialized Core process state, native gRPC operations, isolated Python update tooling.
**Tech Stack:** Rust, Tokio, axum, rustls, tonic/prost; Python standard library; GitHub Actions.
**Spec:** docs/superpowers/specs/2026-11-12-remnanode-design.md

## Constraints
- Pin upstream release 3.4.5 / 4009f09de377cd1011fdfd798d6cc9b690637fb8.
- Keep all 25 public routes and explicit failures for unsupported behavior.
- No secrets committed; no JavaScript runtime; AGPL-3.0-only attribution.
- No destructive rewrite of upstream repository or automatic deployment.

## Tasks
- [ ] Core: test config injection, hashes/restarts, process failure, atomic config permissions; implement native Xray process lifecycle and system info in src/core.rs.
- [ ] RPC: test protobuf payloads/stat grouping and real Xray requests; implement src/grpc.rs and src/operations.rs for user and stats APIs.
- [ ] Frontend: test auth, validation, TLS/SNI, route coverage and errors; implement config/auth/api/main modules and plugins.
- [ ] Updates: test deterministic upstream snapshot, drift and update prompt; implement scripts, contract lock, CI and AI PR workflow.
- [ ] Integrate: run fmt/clippy/test/Python checks and real Xray smoke; review, document limitations, commit and push authorized target.

Shared Core interface: Core::new(binary: PathBuf, state_dir: PathBuf, endpoint: String); pub endpoint:String; pub inbounds:HashMap<String,HashSet<String>>; async start(&mut self, body:&Value)->Result<Value>; async stop(&mut self)->Result<Value>; async health(&mut self)->Value; system_info()->Value; system_stats()->Value. RPC handle(path:&str,body:&Value,core:&mut Core)->Result<Value> returns inner response. Routes wrapped as {response: ...}. Modules may add focused helpers without changing these interfaces.
