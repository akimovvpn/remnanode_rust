pub mod api;
pub mod auth;
pub mod config;
pub mod core;
pub mod grpc;
pub mod operations;
pub mod plugins;

pub fn upstream_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../upstream/manifest.json"))
                .expect("valid supported upstream manifest");
        manifest["tag"]
            .as_str()
            .expect("upstream tag")
            .trim_start_matches('v')
            .to_owned()
    })
}
