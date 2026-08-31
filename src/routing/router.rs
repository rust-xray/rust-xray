use std::sync::{Arc, Mutex, RwLock};

use tracing::debug;

use crate::api::proto::common::serial::TypedMessage;
use crate::config::xray::raw::RoutingConfig;
use crate::dns::engine::DnsEngine;
use crate::routing::compile::{decode_router_config, CompiledRule, RouteTable, RuleCompiler};
use crate::routing::conditions::{ConditionResult, RouteMatchState};
use crate::routing::context::{RouteContext, RouteDecision, RouteError};
use crate::routing::geodata::GeodataCache;
use crate::routing::health::SharedHealthProvider;
use crate::routing::resolver::TargetResolver;
use crate::routing::stats::RoutingStatsChannel;
use crate::routing::webhook::close_webhooks;
use crate::runtime::RuntimeOutboundManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainStrategy {
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

pub struct RuntimeRouter {
    table: RwLock<Arc<RouteTable>>,
    outbound: Arc<RuntimeOutboundManager>,
    dns: Arc<DnsEngine>,
    resolver: Arc<dyn TargetResolver>,
    geodata: GeodataCache,
    domain_strategy: DomainStrategy,
    stats: Option<Arc<RoutingStatsChannel>>,
    observatory_health: Option<SharedHealthProvider>,
    mutation_lock: Mutex<()>,
}

impl RuntimeRouter {
    pub fn new(
        routing: Option<&RoutingConfig>,
        outbound: Arc<RuntimeOutboundManager>,
        dns: Arc<DnsEngine>,
        enable_routing_stats: bool,
        observatory_health: Option<SharedHealthProvider>,
    ) -> Result<Arc<Self>, RouteError> {
        let resolver: Arc<dyn TargetResolver> = dns.clone();
        Self::new_with_resolver(
            routing,
            outbound,
            dns,
            resolver,
            enable_routing_stats,
            observatory_health,
        )
    }

    pub fn new_with_resolver(
        routing: Option<&RoutingConfig>,
        outbound: Arc<RuntimeOutboundManager>,
        dns: Arc<DnsEngine>,
        resolver: Arc<dyn TargetResolver>,
        enable_routing_stats: bool,
        observatory_health: Option<SharedHealthProvider>,
    ) -> Result<Arc<Self>, RouteError> {
        let geodata = GeodataCache::default();
        let compiler = RuleCompiler::with_observatory_health(
            Arc::clone(&outbound),
            geodata.clone(),
            observatory_health.clone(),
        );
        let table = compiler.compile_startup_table(routing)?;
        let domain_strategy = routing
            .and_then(|routing| routing.domain_strategy.as_deref())
            .map(parse_domain_strategy)
            .unwrap_or(DomainStrategy::AsIs);
        Ok(Arc::new(Self {
            table: RwLock::new(Arc::new(table)),
            outbound,
            dns,
            resolver,
            geodata,
            domain_strategy,
            stats: enable_routing_stats.then(|| Arc::new(RoutingStatsChannel::new())),
            observatory_health,
            mutation_lock: Mutex::new(()),
        }))
    }

    pub fn routing_stats(&self) -> Option<Arc<RoutingStatsChannel>> {
        self.stats.clone()
    }

    pub fn outbound_manager(&self) -> &Arc<RuntimeOutboundManager> {
        &self.outbound
    }

    pub fn health_provider(&self) -> SharedHealthProvider {
        self.observatory_health
            .clone()
            .unwrap_or_else(|| Arc::new(crate::routing::health::NoOutboundHealthProvider))
    }

    pub fn domain_strategy(&self) -> DomainStrategy {
        self.domain_strategy
    }

    pub fn dns_engine(&self) -> &Arc<DnsEngine> {
        &self.dns
    }

    pub async fn pick_route(&self, mut ctx: RouteContext) -> Result<RouteDecision, RouteError> {
        let table = Arc::clone(&*self.table.read().expect("router table lock"));
        self.pick_route_with_table(&table, &mut ctx).await
    }

    pub async fn pick_route_with_default(
        &self,
        mut ctx: RouteContext,
    ) -> Result<RouteDecision, RouteError> {
        let table = Arc::clone(&*self.table.read().expect("router table lock"));
        match self.pick_route_with_table(&table, &mut ctx).await {
            Ok(decision) => Ok(decision),
            Err(RouteError::NoClue) => {
                let Some(outbound_tag) = self.outbound.default_tag() else {
                    debug!(
                        inbound_tag = %ctx.inbound_tag,
                        network = ctx.network.as_str(),
                        target_domain = %ctx.target_domain,
                        target_port = ctx.target_port,
                        outbound_count = self.outbound.registered_outbound_count(),
                        "routing: no matching rule and no default outbound registered"
                    );
                    return Err(RouteError::NoClue);
                };
                debug!(
                    inbound_tag = %ctx.inbound_tag,
                    network = ctx.network.as_str(),
                    target_domain = %ctx.target_domain,
                    target_port = ctx.target_port,
                    outbound_tag = %outbound_tag,
                    "routing: no matching rule; using default outbound"
                );
                Ok(RouteDecision {
                    context: ctx,
                    outbound_tag,
                    outbound_group_tags: Vec::new(),
                    rule_tag: String::new(),
                })
            }
            Err(err) => Err(err),
        }
    }

    pub fn publish_route(&self, decision: &RouteDecision) {
        if let Some(stats) = &self.stats {
            stats.publish(decision.clone());
        }
    }

    pub fn add_rule(&self, config: &TypedMessage, should_append: bool) -> Result<(), RouteError> {
        let _guard = self.mutation_lock.lock().expect("router mutation lock");
        let decoded = decode_router_config(config)?;
        let current = Arc::clone(&*self.table.read().expect("router table lock"));
        let compiler = RuleCompiler::with_observatory_health(
            Arc::clone(&self.outbound),
            self.geodata.clone(),
            self.observatory_health.clone(),
        );
        let next = compiler.reload_table(&current, &decoded, should_append)?;
        *self.table.write().expect("router table lock") = Arc::new(next);
        if !should_append {
            close_webhooks(&current.rules);
        }
        Ok(())
    }

    pub fn remove_rule(&self, rule_tag: &str) -> Result<(), RouteError> {
        if rule_tag.is_empty() {
            return Err(RouteError::InvalidArgument("empty tag name!".to_string()));
        }
        let _guard = self.mutation_lock.lock().expect("router mutation lock");
        let current = Arc::clone(&*self.table.read().expect("router table lock"));
        let (rules, removed): (Vec<_>, Vec<_>) = current
            .rules
            .iter()
            .cloned()
            .partition(|rule| rule.rule_tag != rule_tag);
        *self.table.write().expect("router table lock") = Arc::new(RouteTable {
            rules,
            balancers: current.balancers.clone(),
        });
        close_webhooks(&removed);
        Ok(())
    }

    pub fn list_rules(&self) -> Vec<(String, String)> {
        let table = Arc::clone(&*self.table.read().expect("router table lock"));
        table
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.outbound_tag.clone().unwrap_or_default(),
                    rule.rule_tag.clone(),
                )
            })
            .collect()
    }

    pub fn get_balancer_override(&self, tag: &str) -> Result<String, RouteError> {
        let table = Arc::clone(&*self.table.read().expect("router table lock"));
        let balancer = table
            .balancers
            .get(tag)
            .ok_or_else(|| RouteError::BalancerNotFound(tag.to_string()))?;
        Ok(balancer.override_target())
    }

    pub fn set_balancer_override(&self, tag: &str, target: String) -> Result<(), RouteError> {
        let table = Arc::clone(&*self.table.read().expect("router table lock"));
        let balancer = table
            .balancers
            .get(tag)
            .ok_or_else(|| RouteError::BalancerNotFound(tag.to_string()))?;
        balancer.set_override_target(target);
        Ok(())
    }

    pub fn get_balancer_principle_targets(&self, tag: &str) -> Result<Vec<String>, RouteError> {
        let table = Arc::clone(&*self.table.read().expect("router table lock"));
        let balancer = table
            .balancers
            .get(tag)
            .ok_or_else(|| RouteError::BalancerNotFound(tag.to_string()))?;
        balancer.principle_targets().map_err(RouteError::Balancer)
    }

    async fn pick_route_with_table(
        &self,
        table: &RouteTable,
        ctx: &mut RouteContext,
    ) -> Result<RouteDecision, RouteError> {
        let resolve_on_demand =
            self.domain_strategy == DomainStrategy::IpOnDemand && !ctx.skip_dns_resolve;

        if let Some(decision) = self.match_rules(table, ctx, resolve_on_demand).await? {
            return Ok(decision);
        }

        if self.domain_strategy == DomainStrategy::IpIfNonMatch
            && !ctx.target_domain.is_empty()
            && !ctx.skip_dns_resolve
            && self.resolve_target_ips(ctx).await
        {
            if let Some(decision) = self.match_rules(table, ctx, false).await? {
                return Ok(decision);
            }
        }

        Err(RouteError::NoClue)
    }

    async fn match_rules(
        &self,
        table: &RouteTable,
        ctx: &mut RouteContext,
        resolve_on_demand: bool,
    ) -> Result<Option<RouteDecision>, RouteError> {
        let mut resolution_attempted = false;
        for rule in &table.rules {
            loop {
                let mut state =
                    RouteMatchState::new(ctx, resolve_on_demand && !resolution_attempted);
                match rule.conditions.evaluate(&mut state) {
                    ConditionResult::NoMatch => break,
                    ConditionResult::ResolveTargetIps => {
                        resolution_attempted = true;
                        let _ = self.resolve_target_ips(ctx).await;
                    }
                    ConditionResult::Match => {
                        let mut outbound_group_tags = Vec::new();
                        let outbound_tag =
                            resolve_rule_target(rule, table, &mut outbound_group_tags)?;
                        let decision = RouteDecision {
                            context: ctx.clone(),
                            outbound_tag: outbound_tag.clone(),
                            outbound_group_tags,
                            rule_tag: rule.rule_tag.clone(),
                        };
                        if let Some(webhook) = &rule.webhook {
                            webhook.fire(&decision.context, &outbound_tag);
                        }
                        return Ok(Some(decision));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn resolve_target_ips(&self, ctx: &mut RouteContext) -> bool {
        if !ctx.target_ips.is_empty() {
            return true;
        }
        if ctx.skip_dns_resolve || ctx.target_domain.is_empty() {
            return false;
        }
        match self.resolver.lookup_target_ips(&ctx.target_domain).await {
            Ok(ips) => {
                ctx.target_ips = ips;
                !ctx.target_ips.is_empty()
            }
            Err(_) => false,
        }
    }
}

fn resolve_rule_target(
    rule: &CompiledRule,
    table: &RouteTable,
    outbound_group_tags: &mut Vec<String>,
) -> Result<String, RouteError> {
    if let Some(tag) = &rule.outbound_tag {
        return Ok(tag.clone());
    }
    if let Some(balancer_tag) = &rule.balancer_tag {
        let balancer = table
            .balancers
            .get(balancer_tag)
            .ok_or_else(|| RouteError::BalancerNotFound(balancer_tag.clone()))?;
        outbound_group_tags.push(balancer_tag.clone());
        return balancer.pick_outbound().map_err(RouteError::Balancer);
    }
    Err(RouteError::NoClue)
}

fn parse_domain_strategy(raw: &str) -> DomainStrategy {
    match raw.trim().to_ascii_lowercase().as_str() {
        "ipifnonmatch" => DomainStrategy::IpIfNonMatch,
        "ipondemand" => DomainStrategy::IpOnDemand,
        _ => DomainStrategy::AsIs,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/routing/router.rs"]
mod router_tests;
