//! Port of xray-core app/stats/command and app/proxyman/command gRPC services.
// tonic::Status is the error type gRPC handlers must return; boxing it would not change the wire.
#![allow(clippy::result_large_err)]
use crate::{
    app::{Counted, Instance},
    config,
    vless::uuid_string,
};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tonic::{Status, body::BoxBody, codec::ProstCodec, server::NamedService};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

mod pb {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct TypedMessage {
        #[prost(string, tag = "1")]
        pub r#type: String,
        #[prost(bytes = "vec", tag = "2")]
        pub value: Vec<u8>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct User {
        #[prost(uint32, tag = "1")]
        pub level: u32,
        #[prost(string, tag = "2")]
        pub email: String,
        #[prost(message, optional, tag = "3")]
        pub account: Option<TypedMessage>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct VlessAccount {
        #[prost(string, tag = "1")]
        pub id: String,
        #[prost(string, tag = "2")]
        pub flow: String,
        #[prost(string, tag = "3")]
        pub encryption: String,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct AddUserOperation {
        #[prost(message, optional, tag = "1")]
        pub user: Option<User>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct RemoveUserOperation {
        #[prost(string, tag = "1")]
        pub email: String,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct AlterInboundRequest {
        #[prost(string, tag = "1")]
        pub tag: String,
        #[prost(message, optional, tag = "2")]
        pub operation: Option<TypedMessage>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Empty {}
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetInboundUserRequest {
        #[prost(string, tag = "1")]
        pub tag: String,
        #[prost(string, tag = "2")]
        pub email: String,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetInboundUserResponse {
        #[prost(message, repeated, tag = "1")]
        pub users: Vec<User>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetInboundUsersCountResponse {
        #[prost(int64, tag = "1")]
        pub count: i64,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetStatsRequest {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(bool, tag = "2")]
        pub reset: bool,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Stat {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(int64, tag = "2")]
        pub value: i64,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetStatsResponse {
        #[prost(message, optional, tag = "1")]
        pub stat: Option<Stat>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct QueryStatsRequest {
        #[prost(string, tag = "1")]
        pub pattern: String,
        #[prost(bool, tag = "2")]
        pub reset: bool,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct QueryStatsResponse {
        #[prost(message, repeated, tag = "1")]
        pub stat: Vec<Stat>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct SysStatsResponse {
        #[prost(uint32, tag = "1")]
        pub num_goroutine: u32,
        #[prost(uint32, tag = "2")]
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
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetStatsOnlineIpListResponse {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(map = "string, int64", tag = "2")]
        pub ips: std::collections::HashMap<String, i64>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetAllOnlineUsersResponse {
        #[prost(string, repeated, tag = "1")]
        pub users: Vec<String>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct OnlineIpEntry {
        #[prost(string, tag = "1")]
        pub ip: String,
        #[prost(int64, tag = "2")]
        pub last_seen: i64,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct TrafficUserStat {
        #[prost(int64, tag = "1")]
        pub uplink: i64,
        #[prost(int64, tag = "2")]
        pub downlink: i64,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct UserStat {
        #[prost(string, tag = "1")]
        pub email: String,
        #[prost(message, repeated, tag = "2")]
        pub ips: Vec<OnlineIpEntry>,
        #[prost(message, optional, tag = "3")]
        pub traffic: Option<TrafficUserStat>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetUsersStatsRequest {
        #[prost(bool, tag = "1")]
        pub include_traffic: bool,
        #[prost(bool, tag = "2")]
        pub reset: bool,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetUsersStatsResponse {
        #[prost(message, repeated, tag = "1")]
        pub users: Vec<UserStat>,
    }
}

struct Unary<F>(F);

impl<Q, R, F> tonic::server::UnaryService<Q> for Unary<F>
where
    F: FnMut(Q) -> Result<R, Status>,
    R: Send + 'static,
{
    type Response = R;
    type Future = BoxFuture<Result<tonic::Response<R>, Status>>;
    fn call(&mut self, request: tonic::Request<Q>) -> Self::Future {
        let result = (self.0)(request.into_inner()).map(tonic::Response::new);
        Box::pin(async move { result })
    }
}

async fn unary<Q, R, F>(request: http::Request<BoxBody>, f: F) -> http::Response<BoxBody>
where
    Q: prost::Message + Default + Send + 'static,
    R: prost::Message + Send + 'static,
    F: FnMut(Q) -> Result<R, Status> + Send + 'static,
{
    tonic::server::Grpc::new(ProstCodec::<R, Q>::default())
        .unary(Unary(f), request)
        .await
}

fn unknown(error: anyhow::Error) -> Status {
    Status::unknown(format!("{error:#}"))
}

#[derive(Clone)]
pub struct StatsService<const V2RAY: bool>(Arc<Instance>);

impl<const V2RAY: bool> NamedService for StatsService<V2RAY> {
    const NAME: &'static str = if V2RAY {
        "v2ray.core.app.stats.command.StatsService"
    } else {
        "xray.app.stats.command.StatsService"
    };
}

impl<const V2RAY: bool> tower::Service<http::Request<BoxBody>> for StatsService<V2RAY> {
    type Response = http::Response<BoxBody>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<BoxBody>) -> Self::Future {
        let me = self.0.clone();
        let method = request
            .uri()
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        Box::pin(async move {
            let stats = move || me.clone();
            Ok(match method.as_str() {
                "GetStats" => {
                    let me = stats();
                    unary(request, move |q: pb::GetStatsRequest| {
                        let c = me
                            .stats
                            .get_counter(&q.name)
                            .ok_or_else(|| Status::not_found(format!("{} not found.", q.name)))?;
                        let value = if q.reset { c.set(0) } else { c.value() };
                        Ok(pb::GetStatsResponse {
                            stat: Some(pb::Stat {
                                name: q.name,
                                value,
                            }),
                        })
                    })
                    .await
                }
                "GetStatsOnline" => {
                    let me = stats();
                    unary(request, move |q: pb::GetStatsRequest| {
                        let m = me
                            .stats
                            .get_online_map(&q.name)
                            .ok_or_else(|| Status::not_found(format!("{} not found.", q.name)))?;
                        Ok(pb::GetStatsResponse {
                            stat: Some(pb::Stat {
                                value: m.count() as i64,
                                name: q.name,
                            }),
                        })
                    })
                    .await
                }
                "GetStatsOnlineIpList" => {
                    let me = stats();
                    unary(request, move |q: pb::GetStatsRequest| {
                        let m = me
                            .stats
                            .get_online_map(&q.name)
                            .ok_or_else(|| Status::not_found(format!("{} not found.", q.name)))?;
                        Ok(pb::GetStatsOnlineIpListResponse {
                            ips: m.ips().into_iter().collect(),
                            name: q.name,
                        })
                    })
                    .await
                }
                "GetAllOnlineUsers" => {
                    let me = stats();
                    unary(request, move |_: pb::Empty| {
                        let users = me
                            .stats
                            .online_maps()
                            .into_iter()
                            .filter(|(_, m)| m.count() > 0)
                            .map(|(n, _)| n)
                            .collect();
                        Ok(pb::GetAllOnlineUsersResponse { users })
                    })
                    .await
                }
                "GetUsersStats" => {
                    let me = stats();
                    unary(request, move |q: pb::GetUsersStatsRequest| {
                        let mut users: std::collections::BTreeMap<String, pb::UserStat> =
                            Default::default();
                        for (name, map) in me.stats.online_maps() {
                            if map.count() == 0 {
                                continue;
                            }
                            let rest = name.split_once(">>>").map(|(_, r)| r).unwrap_or_default();
                            let email = rest
                                .split_once(">>>")
                                .map(|(e, _)| e)
                                .unwrap_or(rest)
                                .to_owned();
                            let ips: Vec<_> = map
                                .ips()
                                .into_iter()
                                .map(|(ip, last_seen)| pb::OnlineIpEntry { ip, last_seen })
                                .collect();
                            if !ips.is_empty() {
                                users.insert(
                                    email.clone(),
                                    pb::UserStat {
                                        email,
                                        ips,
                                        traffic: None,
                                    },
                                );
                            }
                        }
                        if q.include_traffic {
                            for u in users.values_mut() {
                                u.traffic = Some(pb::TrafficUserStat::default());
                            }
                            for (name, c) in me.stats.counters() {
                                let (email, up) = if let Some(e) =
                                    name.strip_suffix(">>>traffic>>>uplink")
                                {
                                    (e, true)
                                } else if let Some(e) = name.strip_suffix(">>>traffic>>>downlink") {
                                    (e, false)
                                } else {
                                    continue;
                                };
                                let Some(u) =
                                    users.get_mut(email.get("user>>>".len()..).unwrap_or_default())
                                else {
                                    continue;
                                };
                                let value = if q.reset { c.set(0) } else { c.value() };
                                let t = u.traffic.get_or_insert_default();
                                if up {
                                    t.uplink = value
                                } else {
                                    t.downlink = value
                                }
                            }
                        }
                        Ok(pb::GetUsersStatsResponse {
                            users: users.into_values().collect(),
                        })
                    })
                    .await
                }
                "QueryStats" => {
                    let me = stats();
                    unary(request, move |q: pb::QueryStatsRequest| {
                        let stat = me
                            .stats
                            .counters()
                            .into_iter()
                            .filter(|(name, _)| name.contains(&q.pattern))
                            .map(|(name, c)| pb::Stat {
                                value: if q.reset { c.set(0) } else { c.value() },
                                name,
                            })
                            .collect();
                        Ok(pb::QueryStatsResponse { stat })
                    })
                    .await
                }
                "GetSysStats" => {
                    let me = stats();
                    unary(request, move |_: pb::Empty| {
                        // Go runtime metrics have no Rust equivalent: live tokio tasks stand in for
                        // goroutines, memory is the process RSS; uptime is exact.
                        // SAFETY: sysconf has no preconditions.
                        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
                        let rss = std::fs::read_to_string("/proc/self/statm")
                            .ok()
                            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
                            .map(|pages| pages * page)
                            .unwrap_or_default();
                        let tasks = tokio::runtime::Handle::current()
                            .metrics()
                            .num_alive_tasks();
                        Ok(pb::SysStatsResponse {
                            num_goroutine: tasks as u32,
                            uptime: me.started.elapsed().as_secs() as u32,
                            alloc: rss,
                            sys: rss,
                            ..Default::default()
                        })
                    })
                    .await
                }
                other => Status::unimplemented(format!(
                    "rcore does not implement StatsService/{other} yet"
                ))
                .into_http(),
            })
        })
    }
}

#[derive(Clone)]
pub struct HandlerService<const V2RAY: bool>(Arc<Instance>);

impl<const V2RAY: bool> NamedService for HandlerService<V2RAY> {
    const NAME: &'static str = if V2RAY {
        "v2ray.core.app.proxyman.command.HandlerService"
    } else {
        "xray.app.proxyman.command.HandlerService"
    };
}

fn to_proto(user: &config::User) -> pb::User {
    let account = pb::VlessAccount {
        id: uuid_string(user.id),
        flow: user.flow.clone(),
        encryption: "none".into(),
    };
    pb::User {
        level: user.level,
        email: user.email.clone(),
        account: Some(pb::TypedMessage {
            r#type: "xray.proxy.vless.Account".into(),
            value: prost::Message::encode_to_vec(&account),
        }),
    }
}

fn alter(me: &Instance, q: pb::AlterInboundRequest) -> anyhow::Result<()> {
    let op = q
        .operation
        .ok_or_else(|| anyhow::anyhow!("unknown operation"))?;
    let users = me
        .users
        .get(&q.tag)
        .ok_or_else(|| anyhow::anyhow!("failed to get handler: {}", q.tag))?;
    match op.r#type.as_str() {
        "xray.app.proxyman.command.AddUserOperation" => {
            let add: pb::AddUserOperation = prost::Message::decode(op.value.as_slice())?;
            let user = add
                .user
                .ok_or_else(|| anyhow::anyhow!("failed to parse user"))?;
            let account = user
                .account
                .ok_or_else(|| anyhow::anyhow!("failed to parse user: account is missing"))?;
            anyhow::ensure!(
                account.r#type == "xray.proxy.vless.Account",
                "failed to parse user: rcore only manages VLESS accounts, got {}",
                account.r#type
            );
            let vless: pb::VlessAccount = prost::Message::decode(account.value.as_slice())?;
            anyhow::ensure!(
                vless.flow.is_empty() || vless.flow == crate::vless::XRV,
                "failed to parse user: unknown flow {}",
                vless.flow
            );
            users.add(config::User {
                email: user.email,
                level: user.level,
                id: config::parse_uuid(&vless.id)?,
                flow: vless.flow,
            })
        }
        "xray.app.proxyman.command.RemoveUserOperation" => {
            let remove: pb::RemoveUserOperation = prost::Message::decode(op.value.as_slice())?;
            users.remove(&remove.email)
        }
        other => anyhow::bail!("not an inbound operation: {other}"),
    }
}

impl<const V2RAY: bool> tower::Service<http::Request<BoxBody>> for HandlerService<V2RAY> {
    type Response = http::Response<BoxBody>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<BoxBody>) -> Self::Future {
        let me = self.0.clone();
        let method = request
            .uri()
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        Box::pin(async move {
            Ok(match method.as_str() {
                "AlterInbound" => {
                    unary(request, move |q: pb::AlterInboundRequest| {
                        alter(&me, q).map(|()| pb::Empty {}).map_err(unknown)
                    })
                    .await
                }
                "GetInboundUsers" => {
                    unary(request, move |q: pb::GetInboundUserRequest| {
                        let users = me.users.get(&q.tag).ok_or_else(|| {
                            unknown(anyhow::anyhow!("failed to get handler: {}", q.tag))
                        })?;
                        let list = if q.email.is_empty() {
                            users.all().iter().map(|u| to_proto(u)).collect()
                        } else {
                            vec![
                                users
                                    .by_email(&q.email)
                                    .map(|u| to_proto(&u))
                                    .unwrap_or_default(),
                            ]
                        };
                        Ok(pb::GetInboundUserResponse { users: list })
                    })
                    .await
                }
                "GetInboundUsersCount" => {
                    unary(request, move |q: pb::GetInboundUserRequest| {
                        let users = me.users.get(&q.tag).ok_or_else(|| {
                            unknown(anyhow::anyhow!("failed to get handler: {}", q.tag))
                        })?;
                        Ok(pb::GetInboundUsersCountResponse {
                            count: users.all().len() as i64,
                        })
                    })
                    .await
                }
                other => Status::unimplemented(format!(
                    "rcore does not implement HandlerService/{other} yet"
                ))
                .into_http(),
            })
        })
    }
}

pub async fn serve(
    me: Arc<Instance>,
    incoming: impl tokio_stream::Stream<Item = std::io::Result<Counted<tokio::net::TcpStream>>>
    + Send
    + 'static,
) -> anyhow::Result<()> {
    tonic::transport::Server::builder()
        .add_service(StatsService::<false>(me.clone()))
        .add_service(StatsService::<true>(me.clone()))
        .add_service(HandlerService::<false>(me.clone()))
        .add_service(HandlerService::<true>(me))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}
