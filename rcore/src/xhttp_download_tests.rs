use super::*;
use serde_json::json;

#[test]
fn server_only_download_settings_do_not_require_a_client_destination() {
    for stream in [json!({}), json!({"network":"tcp"})] {
        let mut profile = json!({"inbounds":[{"port":1080, "protocol":"vless",
            "settings":{"clients":[], "decryption":"none"},
            "streamSettings":{"network":"xhttp", "xhttpSettings":{"downloadSettings":stream}}
        }]});
        assert!(crate::config::Config::parse(&profile.to_string()).is_ok());
        profile["inbounds"][0]["streamSettings"]["xhttpSettings"]["mode"] = json!("stream-one");
        assert!(crate::config::Config::parse(&profile.to_string()).is_err());
    }
    for invalid in [json!(false), json!([]), json!("not a stream")] {
        assert!(crate::config::Config::parse(&json!({"inbounds":[{
            "port":1080,"protocol":"vless","settings":{"clients":[],"decryption":"none"},
            "streamSettings":{"network":"xhttp","xhttpSettings":{"downloadSettings":invalid}}
        }]}).to_string()).is_err());
    }
}

#[test]
fn download_address_expands_environment_and_normalizes_tls_default_name() {
    for (input, expected) in [
        ("[::1]".to_owned(), "::1".to_owned()),
        (
            "env:RCORERUN_MISSING_DOWNLOAD_ADDRESS_83E919".to_owned(),
            String::new(),
        ),
        ("env:PATH".to_owned(), std::env::var("PATH").unwrap()),
    ] {
        let config = Config::parse(
            &json!({"downloadSettings":{
                "address":input, "network":"xhttp", "security":"tls"
            }}),
            "x",
        )
        .unwrap();
        let down = config.download.as_ref().unwrap();
        assert_eq!(
            down.address.to_string(),
            if expected == "::1" {
                "[::1]"
            } else {
                &expected
            }
        );
        let Security::Tls(tls) = &down.security else {
            panic!("expected TLS");
        };
        assert_eq!(tls.server_name, expected);
    }
}

#[test]
fn download_stream_uses_its_own_endpoint_and_request_settings() {
    let config = Config::parse(
        &json!({
            "host":"upload.test", "path":"/upload?from=parent", "mode":"stream-up",
            "headers":{"X-Parent":"upload"}, "xmux":{"maxConnections":1},
            "downloadSettings":{
                "address":"download.test", "port":8443,
                "network":"tcp", "method":"SplitHTTP", "security":"TLS",
                "tlsSettings":{"serverName":"download-sni.test"},
                "splithttpSettings":{"path":"/ignored"},
                "xhttpSettings":{
                    "host":"download-host.test", "path":"/download?from=child",
                    "headers":{"X-Child":"download"}, "uplinkHTTPMethod":"PATCH",
                    "xPaddingBytes":1, "xmux":{"maxConnections":2}
                }
            }
        }),
        "x",
    )
    .unwrap();
    let download = config.download.as_ref().unwrap();
    assert_eq!(download.address.to_string(), "download.test");
    assert_eq!(download.port, 8443);
    let Security::Tls(tls) = &download.security else {
        panic!("download security must be independent TLS");
    };
    assert_eq!(tls.server_name, "download-sni.test");
    assert_eq!(config.xmux.max_connections, (1, 1));
    let child = &download.client.config;
    assert_eq!(child.xmux.max_connections, (2, 2));
    assert_eq!(child.server.host, "download-host.test");
    assert_eq!(child.method, http::Method::PATCH);
    let (request, body) = child
        .request("https", "download-host.test", "session", None, None, false)
        .unwrap();
    assert_eq!(request.method(), http::Method::GET);
    assert_eq!(
        request.uri(),
        "https://download-host.test/download/session?from=child"
    );
    assert_eq!(request.headers()["x-child"], "download");
    assert!(!request.headers().contains_key("x-parent"));
    assert!(!request.headers().contains_key("content-type"));
    assert!(body.is_empty());
}

#[test]
fn download_defaults_do_not_inherit_parent_values() {
    let config = Config::parse(
        &json!({
            "host":"upload.test", "path":"/upload?parent=1", "mode":"stream-up",
            "headers":{"X-Parent":"upload"}, "xmux":{"maxConnections":1},
            "downloadSettings":{"address":"download.test", "network":"xhttp"}
        }),
        "x",
    )
    .unwrap();
    let download = config.download.as_ref().unwrap();
    assert_eq!(download.port, 0);
    assert!(matches!(download.security, Security::None));
    let child = &download.client.config;
    assert_eq!(child.server.host, "");
    assert_eq!(child.server.path, "/");
    assert_eq!(child.query, "");
    assert_eq!(child.server.mode, "auto");
    assert_eq!(child.xmux.max_connections, (3, 3));
    let (request, _) = child
        .request("http", "download.test", "session", None, None, false)
        .unwrap();
    assert_eq!(request.uri(), "http://download.test/session");
    assert!(!request.headers().contains_key("x-parent"));
}

#[test]
fn download_transport_aliases_accept_method_override() {
    for stream in [
        json!({"address":"download.test", "network":"xhttp"}),
        json!({"address":"download.test", "network":"SPLITHTTP"}),
        json!({"address":"download.test", "network":"tcp", "method":"XHTTP"}),
        json!({"address":"", "network":"xhttp"}),
    ] {
        let config = Config::parse(&json!({"downloadSettings":stream}), "x").unwrap();
        assert!(config.download.is_some());
    }
}

#[test]
fn download_stream_field_names_follow_go_case_insensitive_matching() {
    let config = Config::parse(
        &json!({"downloadSettings":{
            "ADDRESS":"download.test", "PORT":8443, "NETWORK":"XHTTP",
            "XHTTPSettings":{"path":"/download"}
        }}),
        "x",
    )
    .unwrap();
    let download = config.download.as_ref().unwrap();
    assert_eq!(download.address.to_string(), "download.test");
    assert_eq!(download.port, 8443);
    assert_eq!(download.client.config.server.path, "/download/");
}

#[test]
fn download_address_normalization_also_sets_default_tls_server_name() {
    for (address, expected) in [
        ("[::1]", "::1"),
        (" 127.0.0.1 ", "127.0.0.1"),
        (" download.test ", "download.test"),
    ] {
        let config = Config::parse(
            &json!({"downloadSettings":{
                "address":address, "network":"xhttp", "security":"tls"
            }}),
            "x",
        )
        .unwrap();
        let download = config.download.as_ref().unwrap();
        assert_eq!(
            download.address.to_string(),
            if expected == "::1" { "[::1]" } else { expected }
        );
        let Security::Tls(tls) = &download.security else {
            panic!("download security must be TLS");
        };
        assert_eq!(tls.server_name, expected);
    }
}

#[test]
fn extra_replaces_download_settings_while_outer_path_and_mode_win() {
    let config = Config::parse(
        &json!({
            "path":"/upload", "mode":"stream-up", "headers":{"X-Ignored":"outer"},
            "downloadSettings":{"address":"ignored.test", "network":"xhttp"},
            "extra":{
                "path":"/ignored", "mode":"stream-one",
                "downloadSettings":{
                    "address":"selected.test", "network":"xhttp",
                    "xhttpSettings":{"path":"/selected"}
                }
            }
        }),
        "x",
    )
    .unwrap();
    assert_eq!(config.server.path, "/upload/");
    assert_eq!(config.server.mode, "stream-up");
    assert_eq!(
        config.download.as_ref().unwrap().address.to_string(),
        "selected.test"
    );
    for extra in [json!({}), serde_json::Value::Null] {
        let config = Config::parse(
            &json!({
                "path":"/upload", "headers":{"X-Ignored":"outer"},
                "downloadSettings":{"address":"ignored.test", "network":"xhttp"},
                "extra":extra
            }),
            "x",
        )
        .unwrap();
        assert!(config.download.is_none());
        let (request, _) = config
            .request("http", "upload.test", "session", None, None, false)
            .unwrap();
        assert!(!request.headers().contains_key("x-ignored"));
        assert_eq!(request.uri(), "http://upload.test/upload/session");
    }
}

#[test]
fn stream_one_rejects_only_effective_download_settings() {
    let stream = json!({"address":"download.test", "network":"xhttp"});
    for config in [
        json!({"mode":"stream-one", "downloadSettings":stream}),
        json!({"mode":"stream-one", "extra":{"downloadSettings":stream}}),
    ] {
        let error = Config::parse(&config, "x").err().unwrap();
        assert!(error.to_string().contains("stream-one"));
    }
    assert!(
        Config::parse(
            &json!({"mode":"stream-one", "downloadSettings":stream, "extra":{}}),
            "x"
        )
        .is_ok()
    );
}

#[test]
fn invalid_or_unported_download_streams_are_rejected_explicitly() {
    for stream in [
        json!({"network":"xhttp"}),
        json!({"address":"download.test"}),
        json!({"address":"download.test", "network":"tcp"}),
        json!({"address":"download.test", "network":"unknown"}),
        json!({"address":false, "network":"xhttp"}),
        json!({"address":"download.test", "network":"xhttp", "port":65536}),
        json!({"address":"download.test", "network":"xhttp", "port":-1}),
        json!({
            "address":"download.test", "network":"xhttp", "security":"tls",
            "tlsSettings":{"alpn":["h3"]}
        }),
    ] {
        assert!(
            Config::parse(&json!({"downloadSettings":stream}), "x").is_err(),
            "accepted invalid/unported download stream: {stream}"
        );
    }
}

#[test]
fn nested_download_configs_are_parsed_and_validated() {
    let mut settings = json!({"downloadSettings":{
        "address":"child.test", "network":"xhttp", "xhttpSettings":{
            "path":"/child", "downloadSettings":{
                "address":"grandchild.test", "network":"xhttp",
                "xhttpSettings":{"path":"/grandchild"}
            }
        }
    }});
    let config = Config::parse(&settings, "x").unwrap();
    let child = &config.download.as_ref().unwrap().client.config;
    assert_eq!(child.server.path, "/child/");
    let grandchild = child.download.as_ref().unwrap();
    assert_eq!(grandchild.address.to_string(), "grandchild.test");
    assert_eq!(grandchild.client.config.server.path, "/grandchild/");
    settings["downloadSettings"]["xhttpSettings"]["downloadSettings"]["xhttpSettings"]["mode"] =
        json!("invalid");
    assert!(Config::parse(&settings, "x").is_err());
}

#[test]
fn download_socket_options_are_parsed_independently() {
    let config = Config::parse(
        &json!({"downloadSettings":{
            "address":"download.test", "network":"xhttp",
            "sockopt":{"interface":"child0", "tcpFastOpen":false, "penetrate":true}
        }}),
        "x",
    )
    .unwrap();
    let socket = &config.download.as_ref().unwrap().socket;
    assert_eq!(socket.interface, "child0");
    assert_eq!(socket.tcp_fast_open, Some(false));
    assert!(socket.penetrate);
}

#[test]
fn auto_mode_splits_reality_only_when_a_download_stream_is_configured() {
    let metadata = crate::tls_client::Client {
        server_name: "server.test".to_owned(),
        fingerprint: crate::tls_client::Fingerprint::Chrome,
        alpn: vec!["h2".to_owned()],
        reality: None,
    };
    let none = Security::None;
    let tls = Security::Tls(metadata.clone());
    let reality = Security::Reality(metadata);
    for separate_download in [false, true] {
        let mut settings = json!({});
        if separate_download {
            settings["downloadSettings"] = json!({"address":"download.test", "network":"xhttp"});
        }
        let client = Client::new(Config::parse(&settings, "x").unwrap());
        assert_eq!(client.mode(&none), "packet-up");
        assert_eq!(client.mode(&tls), "packet-up");
        assert_eq!(
            client.mode(&reality),
            if separate_download {
                "stream-up"
            } else {
                "stream-one"
            }
        );
        settings["mode"] = json!("stream-up");
        let client = Client::new(Config::parse(&settings, "x").unwrap());
        for security in [&none, &tls, &reality] {
            assert_eq!(client.mode(security), "stream-up");
        }
    }
}
