use super::*;

#[test]
fn same_ip_two_refs_count_one_until_both_removed() {
    let map = OnlineMap::new();
    map.add_ip("1.2.3.4", 100);
    map.add_ip("1.2.3.4", 101);
    assert_eq!(map.count(), 1);
    map.remove_ip("1.2.3.4");
    assert_eq!(map.count(), 1);
    map.remove_ip("1.2.3.4");
    assert_eq!(map.count(), 0);
}

#[test]
fn different_ips_increase_unique_count() {
    let map = OnlineMap::new();
    map.add_ip("1.2.3.4", 100);
    map.add_ip("5.6.7.8", 101);
    assert_eq!(map.count(), 2);
    map.remove_ip("1.2.3.4");
    assert_eq!(map.count(), 1);
}

#[test]
fn loopback_ips_are_ignored() {
    let map = OnlineMap::new();
    map.add_ip("127.0.0.1", 100);
    map.add_ip("[::1]", 100);
    map.add_ip("::1", 100);
    assert_eq!(map.count(), 0);
}

#[test]
fn duplicate_remove_is_safe() {
    let map = OnlineMap::new();
    map.add_ip("1.2.3.4", 100);
    map.remove_ip("1.2.3.4");
    map.remove_ip("1.2.3.4");
    assert_eq!(map.count(), 0);
}

#[test]
fn add_updates_last_seen() {
    let map = OnlineMap::new();
    map.add_ip("1.2.3.4", 100);
    map.add_ip("1.2.3.4", 200);
    let mut last_seen = 0;
    map.for_each(|_, seen| {
        last_seen = seen;
        true
    });
    assert_eq!(last_seen, 200);
}
