#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_payload_uses_xray_type_name_without_any_prefix() {
        let payload = typed(
            "xray.proxy.trojan.Account",
            &SingleString {
                value: "secret".into(),
            },
        );
        assert_eq!(payload.r#type, "xray.proxy.trojan.Account");
        assert_eq!(payload.value, b"\x0a\x06secret");
    }
    #[test]
    fn system_stats_wire_fields_decode() {
        let response = SysStats::decode(&b"\x08\x04\x18\x64\x50\x02"[..]).unwrap();
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["numGoroutine"], 4);
        assert_eq!(json["alloc"], 100);
        assert_eq!(json["uptime"], 2);
    }
}

use anyhow::{Context, Result};
use prost::Message;
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, time::Duration};
use tonic::{
    client::Grpc as Client,
    codec::ProstCodec,
    transport::{Channel, Endpoint},
};

// Wire fields match @remnawave/xtls-sdk 0.17.0's bundled Xray protobufs.
#[derive(Clone, PartialEq, Message)]
pub struct Empty {}
#[derive(Clone, PartialEq, Message)]
pub struct TypedMessage {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}
pub fn typed<T: Message>(name: &str, message: &T) -> TypedMessage {
    TypedMessage {
        r#type: name.into(),
        value: message.encode_to_vec(),
    }
}
#[derive(Clone, PartialEq, Message)]
pub struct SingleString {
    #[prost(string, tag = "1")]
    pub value: String,
}
#[derive(Clone, PartialEq, Message)]
pub struct VlessAccount {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub flow: String,
    #[prost(string, tag = "3")]
    pub encryption: String,
}
#[derive(Clone, PartialEq, Message)]
pub struct ShadowsocksAccount {
    #[prost(string, tag = "1")]
    pub password: String,
    #[prost(int32, tag = "2")]
    pub cipher_type: i32,
    #[prost(bool, tag = "3")]
    pub iv_check: bool,
}
#[derive(Clone, PartialEq, Message)]
pub struct User {
    #[prost(uint32, tag = "1")]
    pub level: u32,
    #[prost(string, tag = "2")]
    pub email: String,
    #[prost(message, optional, tag = "3")]
    pub account: Option<TypedMessage>,
}
#[derive(Clone, PartialEq, Message)]
pub struct AddUser {
    #[prost(message, optional, tag = "1")]
    pub user: Option<User>,
}
#[derive(Clone, PartialEq, Message)]
pub struct AlterInbound {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(message, optional, tag = "2")]
    pub operation: Option<TypedMessage>,
}
#[derive(Clone, PartialEq, Message)]
pub struct StatsRequest {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}
#[derive(Clone, PartialEq, Message)]
pub struct Stat {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int64, tag = "2")]
    pub value: i64,
}
#[derive(Clone, PartialEq, Message)]
pub struct StatsResponse {
    #[prost(message, repeated, tag = "1")]
    pub stat: Vec<Stat>,
}
#[derive(Clone, PartialEq, Message)]
pub struct StatResponse {
    #[prost(message, optional, tag = "1")]
    pub stat: Option<Stat>,
}
#[derive(Clone, PartialEq, Message)]
pub struct IpResponse {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(map = "string, int64", tag = "2")]
    pub ips: HashMap<String, i64>,
}
#[derive(Clone, PartialEq, Message)]
pub struct OnlineUsers {
    #[prost(string, repeated, tag = "1")]
    pub users: Vec<String>,
}
#[derive(Clone, PartialEq, Message)]
pub struct UsersRequest {
    #[prost(bool, tag = "1")]
    pub include_traffic: bool,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}
#[derive(Clone, PartialEq, Message)]
pub struct OnlineIp {
    #[prost(string, tag = "1")]
    pub ip: String,
    #[prost(int64, tag = "2")]
    pub last_seen: i64,
}
#[derive(Clone, PartialEq, Message)]
pub struct UserTraffic {
    #[prost(int64, tag = "1")]
    pub uplink: i64,
    #[prost(int64, tag = "2")]
    pub downlink: i64,
}
#[derive(Clone, PartialEq, Message)]
pub struct UserStat {
    #[prost(string, tag = "1")]
    pub email: String,
    #[prost(message, repeated, tag = "2")]
    pub ips: Vec<OnlineIp>,
    #[prost(message, optional, tag = "3")]
    pub traffic: Option<UserTraffic>,
}
#[derive(Clone, PartialEq, Message)]
pub struct UsersResponse {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<UserStat>,
}
#[derive(Clone, PartialEq, Message, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SysStats {
    #[prost(uint32, tag = "1")]
    pub num_goroutine: u32,
    #[prost(uint32, tag = "2")]
    #[serde(rename = "numGC")]
    pub num_gc: u32,
    #[prost(uint64, tag = "3")]
    pub alloc: u64,
    #[prost(uint64, tag = "4")]
    pub total_alloc: u64,
    #[prost(uint64, tag = "5")]
    pub sys: u64,
    #[prost(uint64, tag = "6")]
    pub mallocs: u64,
    #[prost(uint64, tag = "7")]
    pub frees: u64,
    #[prost(uint64, tag = "8")]
    pub live_objects: u64,
    #[prost(uint64, tag = "9")]
    pub pause_total_ns: u64,
    #[prost(uint32, tag = "10")]
    pub uptime: u32,
}

pub struct Grpc {
    client: Client<Channel>,
}
impl Grpc {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let url = if endpoint.starts_with("http://") {
            endpoint.to_owned()
        } else {
            format!("http://{endpoint}")
        };
        let channel = Endpoint::from_shared(url)?
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .context("connect to Xray gRPC")?;
        Ok(Self {
            client: Client::new(channel).max_decoding_message_size(64 * 1024 * 1024),
        })
    }
    pub async fn call<
        Q: Message + Default + Send + Sync + 'static,
        R: Message + Default + Send + Sync + 'static,
    >(
        &mut self,
        path: &'static str,
        request: Q,
    ) -> Result<R> {
        self.client
            .ready()
            .await
            .context("Xray gRPC channel readiness")?;
        Ok(self
            .client
            .unary(
                tonic::Request::new(request),
                tonic::codegen::http::uri::PathAndQuery::from_static(path),
                ProstCodec::default(),
            )
            .await?
            .into_inner())
    }
    pub async fn sys_stats(&mut self) -> Result<Value> {
        let stats: SysStats = self
            .call("/xray.app.stats.command.StatsService/GetSysStats", Empty {})
            .await?;
        Ok(serde_json::to_value(stats)?)
    }
    pub async fn query(&mut self, pattern: &str, reset: bool) -> Result<Vec<Stat>> {
        let response: StatsResponse = self
            .call(
                "/xray.app.stats.command.StatsService/QueryStats",
                StatsRequest {
                    name: pattern.into(),
                    reset,
                },
            )
            .await?;
        Ok(response.stat)
    }
    pub async fn ips(&mut self, username: &str, reset: bool) -> Result<HashMap<String, i64>> {
        let response: Result<IpResponse> = self
            .call(
                "/xray.app.stats.command.StatsService/GetStatsOnlineIpList",
                StatsRequest {
                    name: format!("user>>>{username}>>>online"),
                    reset,
                },
            )
            .await;
        match response {
            Ok(r) => Ok(r.ips),
            Err(e) if is_not_found(&e) => Ok(HashMap::new()),
            Err(e) => Err(e),
        }
    }
    pub async fn add(&mut self, tag: &str, user: User) -> Result<()> {
        let _: Empty = self
            .call(
                "/xray.app.proxyman.command.HandlerService/AlterInbound",
                AlterInbound {
                    tag: tag.into(),
                    operation: Some(typed(
                        "xray.app.proxyman.command.AddUserOperation",
                        &AddUser { user: Some(user) },
                    )),
                },
            )
            .await?;
        Ok(())
    }
    pub async fn remove(&mut self, tag: &str, username: &str) -> Result<()> {
        let result: Result<Empty> = self
            .call(
                "/xray.app.proxyman.command.HandlerService/AlterInbound",
                AlterInbound {
                    tag: tag.into(),
                    operation: Some(typed(
                        "xray.app.proxyman.command.RemoveUserOperation",
                        &SingleString {
                            value: username.into(),
                        },
                    )),
                },
            )
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e)
                if is_not_found(&e)
                    || e.downcast_ref::<tonic::Status>().is_some_and(|s| {
                        s.message().to_ascii_lowercase().contains("user ")
                            && s.message().contains("not found")
                    }) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
pub fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<tonic::Status>()
        .is_some_and(|s| s.code() == tonic::Code::NotFound)
}
