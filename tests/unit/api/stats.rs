use super::*;
use std::sync::Arc;

use crate::stats::{user_online, user_traffic_downlink, user_traffic_uplink, StatsRegistry};
use tonic::Request;

fn service(registry: Arc<StatsRegistry>) -> StatsServiceImpl {
    StatsServiceImpl::new(registry)
}

#[tokio::test]
async fn get_stats_online_reset_is_ignored() {
    let registry = Arc::new(StatsRegistry::new());
    let map = registry.get_or_register_online_map(&user_online("user@example.com"));
    map.add_ip("1.2.3.4", 100);

    let svc = service(Arc::clone(&registry));
    let resp = svc
        .get_stats_online(Request::new(GetStatsRequest {
            name: user_online("user@example.com"),
            reset: true,
        }))
        .await
        .expect("get_stats_online")
        .into_inner();
    assert_eq!(resp.stat.expect("stat").value, 1);
    assert_eq!(map.count(), 1);
}

#[tokio::test]
async fn get_stats_online_ip_list_returns_latest_last_seen() {
    let registry = Arc::new(StatsRegistry::new());
    let map = registry.get_or_register_online_map(&user_online("user@example.com"));
    map.add_ip("1.2.3.4", 100);
    map.add_ip("1.2.3.4", 200);

    let svc = service(Arc::clone(&registry));
    let resp = svc
        .get_stats_online_ip_list(Request::new(GetStatsRequest {
            name: user_online("user@example.com"),
            reset: false,
        }))
        .await
        .expect("ip list")
        .into_inner();
    assert_eq!(resp.ips.len(), 1);
    assert_eq!(resp.ips.get("1.2.3.4").copied(), Some(200));
}

#[tokio::test]
async fn get_all_online_users_returns_map_names_not_bare_emails() {
    let registry = Arc::new(StatsRegistry::new());
    let name = user_online("user@example.com");
    registry
        .get_or_register_online_map(&name)
        .add_ip("1.2.3.4", 100);

    let svc = service(Arc::clone(&registry));
    let resp = svc
        .get_all_online_users(Request::new(GetAllOnlineUsersRequest {}))
        .await
        .expect("all online")
        .into_inner();
    assert_eq!(resp.users, vec![name]);
}

#[tokio::test]
async fn get_users_stats_include_traffic_false_does_not_reset_counters() {
    let registry = Arc::new(StatsRegistry::new());
    let email = "user@example.com";
    registry
        .get_or_register_online_map(&user_online(email))
        .add_ip("1.2.3.4", 100);
    registry.add(&user_traffic_uplink(email), 100);
    registry.add(&user_traffic_downlink(email), 50);

    let svc = service(Arc::clone(&registry));
    let resp = svc
        .get_users_stats(Request::new(GetUsersStatsRequest {
            reset: true,
            include_traffic: false,
        }))
        .await
        .expect("users stats")
        .into_inner();
    assert_eq!(resp.users.len(), 1);
    assert!(resp.users[0].traffic.is_none());
    assert_eq!(
        registry.get(&user_traffic_uplink(email), false).unwrap(),
        100
    );
    assert_eq!(
        registry.get(&user_traffic_downlink(email), false).unwrap(),
        50
    );
}

#[tokio::test]
async fn get_users_stats_include_traffic_reset_clears_traffic_not_online() {
    let registry = Arc::new(StatsRegistry::new());
    let email = "user@example.com";
    let map = registry.get_or_register_online_map(&user_online(email));
    map.add_ip("1.2.3.4", 100);
    registry.add(&user_traffic_uplink(email), 100);
    registry.add(&user_traffic_downlink(email), 50);

    let svc = service(Arc::clone(&registry));
    let resp = svc
        .get_users_stats(Request::new(GetUsersStatsRequest {
            reset: true,
            include_traffic: true,
        }))
        .await
        .expect("users stats")
        .into_inner();
    let user = &resp.users[0];
    let traffic = user.traffic.as_ref().expect("traffic");
    assert_eq!(traffic.uplink, 100);
    assert_eq!(traffic.downlink, 50);
    assert_eq!(map.count(), 1);

    let resp = svc
        .get_users_stats(Request::new(GetUsersStatsRequest {
            reset: false,
            include_traffic: true,
        }))
        .await
        .expect("users stats again")
        .into_inner();
    let traffic = resp.users[0].traffic.as_ref().expect("traffic");
    assert_eq!(traffic.uplink, 0);
    assert_eq!(traffic.downlink, 0);
    assert_eq!(map.count(), 1);
}

#[tokio::test]
async fn get_users_stats_skips_invalid_online_map_names() {
    let registry = Arc::new(StatsRegistry::new());
    registry
        .get_or_register_online_map("not-a-user-online-key")
        .add_ip("1.2.3.4", 100);
    registry
        .get_or_register_online_map(&user_online("valid@example.com"))
        .add_ip("5.6.7.8", 100);

    let svc = service(Arc::clone(&registry));
    let resp = svc
        .get_users_stats(Request::new(GetUsersStatsRequest {
            reset: false,
            include_traffic: false,
        }))
        .await
        .expect("users stats")
        .into_inner();
    assert_eq!(resp.users.len(), 1);
    assert_eq!(resp.users[0].email, "valid@example.com");
}
