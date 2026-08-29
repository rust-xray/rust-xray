use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::broadcast;

use crate::routing::context::RouteDecision;

const ROUTING_STATS_CAPACITY: usize = 64;

pub struct RoutingStatsChannel {
    sender: broadcast::Sender<RouteDecision>,
    subscribers: AtomicUsize,
}

impl RoutingStatsChannel {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(ROUTING_STATS_CAPACITY);
        Self {
            sender,
            subscribers: AtomicUsize::new(0),
        }
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.load(Ordering::SeqCst)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RouteDecision> {
        self.subscribers.fetch_add(1, Ordering::SeqCst);
        self.sender.subscribe()
    }

    pub fn unsubscribe(&self) {
        self.subscribers.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn publish(&self, decision: RouteDecision) {
        let _ = self.sender.send(decision);
    }
}

impl Default for RoutingStatsChannel {
    fn default() -> Self {
        Self::new()
    }
}
