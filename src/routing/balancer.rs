use std::cmp::Ordering as CmpOrdering;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use regex::Regex;

use crate::routing::health::{
    NoOutboundHealthProvider, OutboundHealthObservation, SharedHealthProvider,
};
use crate::runtime::RuntimeOutboundManager;

#[derive(Debug, Clone)]
pub struct StrategyWeight {
    pub matcher: String,
    pub value: f32,
    pub compiled: Option<Regex>,
}

#[derive(Debug, Clone, Default)]
pub struct LeastLoadConfig {
    pub costs: Vec<StrategyWeight>,
    pub baselines: Vec<i64>,
    pub expected: i32,
    pub max_rtt: i64,
    pub tolerance: f32,
}

#[derive(Debug, Clone)]
pub struct BalancerConfig {
    pub tag: String,
    pub selectors: Vec<String>,
    pub strategy: BalancerStrategy,
    pub fallback_tag: String,
    pub least_load: Option<LeastLoadConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalancerStrategy {
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad,
}

pub struct Balancer {
    config: BalancerConfig,
    outbound: Arc<RuntimeOutboundManager>,
    health: SharedHealthProvider,
    override_target: RwLock<String>,
    round_robin_index: AtomicUsize,
}

impl Balancer {
    pub fn new(
        config: BalancerConfig,
        outbound: Arc<RuntimeOutboundManager>,
        health: Option<SharedHealthProvider>,
    ) -> Self {
        Self {
            config,
            outbound,
            health: health.unwrap_or_else(|| Arc::new(NoOutboundHealthProvider)),
            override_target: RwLock::new(String::new()),
            round_robin_index: AtomicUsize::new(0),
        }
    }

    pub fn override_target(&self) -> String {
        self.override_target
            .read()
            .expect("balancer override lock")
            .clone()
    }

    pub fn set_override_target(&self, target: String) {
        *self
            .override_target
            .write()
            .expect("balancer override lock") = target;
    }

    pub fn principle_targets(&self) -> Result<Vec<String>, String> {
        let candidates = self.select_candidates();
        match self.config.strategy {
            BalancerStrategy::LeastPing => self
                .pick_least_ping(&candidates)
                .map(|tag| tag.into_iter().collect()),
            BalancerStrategy::LeastLoad => self.pick_least_load(&candidates),
            BalancerStrategy::Random | BalancerStrategy::RoundRobin => Ok(candidates),
        }
    }

    pub fn pick_outbound(&self) -> Result<String, String> {
        let override_target = self.override_target();
        if !override_target.is_empty() {
            return Ok(override_target);
        }

        let candidates = self.select_candidates();
        let selected = match self.config.strategy {
            BalancerStrategy::Random => {
                let candidates = self.alive_candidates_when_fallback_enabled(candidates);
                (!candidates.is_empty()).then(|| candidates[random_index(candidates.len())].clone())
            }
            BalancerStrategy::RoundRobin => {
                let candidates = self.alive_candidates_when_fallback_enabled(candidates);
                if candidates.is_empty() {
                    None
                } else {
                    let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
                    Some(candidates[index % candidates.len()].clone())
                }
            }
            BalancerStrategy::LeastPing => self.pick_least_ping(&candidates).unwrap_or(None),
            BalancerStrategy::LeastLoad => {
                let selected = self.pick_least_load(&candidates).unwrap_or_default();
                (!selected.is_empty()).then(|| selected[random_index(selected.len())].clone())
            }
        };

        match selected {
            Some(tag) if !tag.is_empty() => Ok(tag),
            _ if !self.config.fallback_tag.is_empty() => Ok(self.config.fallback_tag.clone()),
            _ => Err("balancing strategy returns empty tag".to_string()),
        }
    }

    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String> {
        self.health.observations()
    }

    fn alive_candidates_when_fallback_enabled(&self, candidates: Vec<String>) -> Vec<String> {
        if self.config.fallback_tag.is_empty() {
            return candidates;
        }
        let Ok(observations) = self.observations() else {
            // Xray keeps the unfiltered candidates when GetObservation fails.
            return candidates;
        };
        candidates
            .into_iter()
            .filter(|candidate| {
                observations
                    .iter()
                    .find(|item| item.outbound_tag == *candidate)
                    .is_none_or(|item| item.alive)
            })
            .collect()
    }

    fn pick_least_ping(&self, candidates: &[String]) -> Result<Option<String>, String> {
        let observations = self.observations()?;
        let mut least_ping = 99_999_999_i64;
        let mut selected = None;
        for observation in observations {
            if observation.alive
                && observation.delay_ms < least_ping
                && candidates.contains(&observation.outbound_tag)
            {
                least_ping = observation.delay_ms;
                selected = Some(observation.outbound_tag);
            }
        }
        Ok(selected)
    }

    fn pick_least_load(&self, candidates: &[String]) -> Result<Vec<String>, String> {
        let settings = self
            .config
            .least_load
            .as_ref()
            .ok_or_else(|| "leastLoad strategy settings are missing".to_string())?;
        let observations = self.observations()?;
        let mut nodes = observations
            .into_iter()
            .filter(|observation| should_select_least_load(observation, candidates, settings))
            .map(|observation| LeastLoadNode::from_observation(observation, settings))
            .collect::<Vec<_>>();
        nodes.sort_by(least_load_order);
        let selected_count = least_load_selected_count(&nodes, settings);
        Ok(nodes
            .into_iter()
            .take(selected_count)
            .map(|node| node.tag)
            .collect())
    }

    fn select_candidates(&self) -> Vec<String> {
        self.outbound.select_outbounds(&self.config.selectors)
    }
}

#[derive(Debug)]
struct LeastLoadNode {
    tag: String,
    count_all: u32,
    count_fail: u32,
    rtt_average: i64,
    rtt_deviation_cost: i64,
}

impl LeastLoadNode {
    fn from_observation(
        observation: OutboundHealthObservation,
        settings: &LeastLoadConfig,
    ) -> Self {
        let (count_all, count_fail, average, deviation) = observation
            .health_ping
            .map(|ping| (ping.all, ping.fail, ping.average, ping.deviation))
            .unwrap_or((
                1,
                1,
                observation.delay_ms * 1_000_000,
                observation.delay_ms * 1_000_000,
            ));
        let cost = strategy_cost(&observation.outbound_tag, &settings.costs);
        let rtt_deviation_cost = (deviation as f64 * (cost as f64).sqrt()) as i64;
        Self {
            tag: observation.outbound_tag,
            count_all,
            count_fail,
            rtt_average: average,
            rtt_deviation_cost,
        }
    }
}

fn should_select_least_load(
    observation: &OutboundHealthObservation,
    candidates: &[String],
    settings: &LeastLoadConfig,
) -> bool {
    if !observation.alive || !candidates.contains(&observation.outbound_tag) {
        return false;
    }
    if settings.max_rtt != 0 && observation.delay_ms >= settings.max_rtt / 1_000_000 {
        return false;
    }
    if let Some(ping) = &observation.health_ping {
        if ping.all > 0
            && settings.tolerance > 0.0
            && ping.fail as f64 / ping.all as f64 > settings.tolerance as f64
        {
            return false;
        }
    }
    true
}

fn least_load_order(left: &LeastLoadNode, right: &LeastLoadNode) -> CmpOrdering {
    left.rtt_deviation_cost
        .cmp(&right.rtt_deviation_cost)
        .then_with(|| left.rtt_average.cmp(&right.rtt_average))
        .then_with(|| left.count_fail.cmp(&right.count_fail))
        .then_with(|| right.count_all.cmp(&left.count_all))
        .then_with(|| left.tag.cmp(&right.tag))
}

fn least_load_selected_count(nodes: &[LeastLoadNode], settings: &LeastLoadConfig) -> usize {
    if nodes.is_empty() {
        return 0;
    }
    let available = nodes.len();
    if settings.expected > available as i32 {
        return available;
    }
    let expected = if settings.expected <= 0 {
        1
    } else {
        settings.expected as usize
    };
    if settings.baselines.is_empty() {
        return expected;
    }
    let mut count = 0;
    for baseline in &settings.baselines {
        for (index, node) in nodes.iter().enumerate().skip(count) {
            if node.rtt_deviation_cost >= *baseline {
                break;
            }
            count = index + 1;
        }
        if count >= expected {
            break;
        }
    }
    if settings.expected > 0 && count < expected {
        expected
    } else {
        count
    }
}

fn strategy_cost(tag: &str, settings: &[StrategyWeight]) -> f32 {
    for weight in settings {
        let matched = if let Some(regex) = &weight.compiled {
            regex.find(tag).map(|value| value.as_str())
        } else {
            tag.find(&weight.matcher).map(|_| weight.matcher.as_str())
        };
        let Some(matched) = matched else {
            continue;
        };
        if weight.value > 0.0 {
            return weight.value;
        }
        return first_number(matched).unwrap_or(1.0);
    }
    1.0
}

fn first_number(value: &str) -> Option<f32> {
    let start = value.find(|character: char| character.is_ascii_digit())?;
    let number = value[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect::<String>();
    number.parse().ok()
}

fn random_index(len: usize) -> usize {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    u64::from_le_bytes(bytes) as usize % len
}

pub fn balancer_requires_observatory(strategy: BalancerStrategy, fallback_tag: &str) -> bool {
    match strategy {
        BalancerStrategy::LeastPing | BalancerStrategy::LeastLoad => true,
        BalancerStrategy::Random | BalancerStrategy::RoundRobin => !fallback_tag.is_empty(),
    }
}

pub fn parse_strategy(raw: &str) -> Result<BalancerStrategy, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "random" => Ok(BalancerStrategy::Random),
        "roundrobin" => Ok(BalancerStrategy::RoundRobin),
        "leastping" => Ok(BalancerStrategy::LeastPing),
        "leastload" => Ok(BalancerStrategy::LeastLoad),
        other => Err(format!("unrecognized balancer type: {other}")),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/routing/balancer.rs"]
mod tests;
