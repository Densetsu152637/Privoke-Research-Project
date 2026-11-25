//! Per-RPC authorisation: the registry, the (role, RPC) policy, per-peer rate limiting and the tower layer that
//! applies them to every request before the service sees it.
//!
//! Decision order for each request: the RPC must be in the policy (otherwise `UNIMPLEMENTED`, the in-service
//! equivalent of nginx's 404); the connection must carry a verified identity (otherwise `UNAUTHENTICATED`); the peer
//! must be inside its rate limit (`RESOURCE_EXHAUSTED`); the registry, read afresh on every request so that the deny
//! list applies to open connections, must know the identity and not deny it (`PERMISSION_DENIED`); and the role must
//! be one the policy lists for the RPC (`PERMISSION_DENIED`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tonic::Status;
use tower::{Layer, Service};

use crate::identity::{Identity, Principal, Role};
use crate::limits::RateLimit;
use crate::listener::ConnectionInfo;
use crate::registry::SharedRegistry;

/// What a rate bucket is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimiterKey {
    /// The certificate identity (model service: one bucket per installation).
    Identity,
    /// The source IP (telemetry service: every reporter shares one certificate).
    SourceIp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RateKey {
    Identity(Identity),
    Ip(IpAddr),
}

#[derive(Debug, Clone)]
struct Rule {
    roles: Vec<Role>,
    key: LimiterKey,
}

/// Which roles may call which RPC on one listener. Everything not listed is `UNIMPLEMENTED`.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    rules: HashMap<String, Rule>,
}

impl Policy {
    /// An empty policy that allows nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow `roles` to call the RPC at `path` (`/package.Service/Method`), rate-limited by `key`.
    #[must_use]
    pub fn allow(mut self, path: &str, roles: &[Role], key: LimiterKey) -> Self {
        self.rules.insert(path.to_string(), Rule { roles: roles.to_vec(), key });
        self
    }

    /// The listed RPC paths, for documentation and tests.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.rules.keys().map(String::as_str)
    }
}

struct AuthShared {
    policy: Policy,
    registry: SharedRegistry,
    limiter: DefaultKeyedRateLimiter<RateKey>,
}

impl std::fmt::Debug for AuthShared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AuthShared").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl AuthShared {
    fn authorise(&self, path: &str, info: Option<&ConnectionInfo>) -> Result<Principal, Status> {
        let rule = self.policy.rules.get(path).ok_or_else(|| Status::unimplemented("method is not served on this listener"))?;
        let info = info.ok_or_else(|| Status::unauthenticated("connection carries no authenticated peer"))?;
        let identity = info.identity.clone().ok_or_else(|| Status::unauthenticated("a client certificate is required"))?;
        let key = match rule.key {
            LimiterKey::Identity => RateKey::Identity(identity.clone()),
            LimiterKey::SourceIp => RateKey::Ip(info.peer_addr.map_or(IpAddr::from([0, 0, 0, 0]), |address| address.ip())),
        };
        if self.limiter.check_key(&key).is_err() {
            return Err(Status::resource_exhausted("rate limit exceeded"));
        }
        let principal = self.registry.load().resolve(&identity).map_err(|denial| Status::permission_denied(denial.to_string()))?;
        if !rule.roles.contains(&principal.role) {
            return Err(Status::permission_denied("role may not call this method"));
        }
        Ok(principal)
    }
}

/// Tower layer that authorises, rate-limits and annotates every request. Add it with `Server::layer`.
#[derive(Debug, Clone)]
pub struct AuthLayer {
    shared: Arc<AuthShared>,
}

impl AuthLayer {
    /// Combine a policy, a registry and a per-peer rate limit.
    pub fn new(policy: Policy, registry: SharedRegistry, rate: RateLimit) -> Self {
        let burst = NonZeroU32::new(rate.burst).unwrap_or(NonZeroU32::MIN);
        let per_second = NonZeroU32::new(rate.per_second).unwrap_or(NonZeroU32::MIN);
        let limiter = RateLimiter::keyed(Quota::per_second(per_second).allow_burst(burst));
        Self { shared: Arc::new(AuthShared { policy, registry, limiter }) }
    }

    /// Drop limiter state for peers that have been idle long enough to have a full bucket. Call periodically.
    pub fn retain_recent(&self) {
        self.shared.limiter.retain_recent();
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService { inner, shared: self.shared.clone() }
    }
}

/// The service produced by [`AuthLayer`].
#[derive(Debug, Clone)]
pub struct AuthService<S> {
    inner: S,
    shared: Arc<AuthShared>,
}

impl<S, B> Service<http::Request<B>> for AuthService<S>
where
    S: Service<http::Request<B>, Response = http::Response<tonic::body::Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        let decision = self.shared.authorise(request.uri().path(), request.extensions().get::<ConnectionInfo>());
        match decision {
            Ok(principal) => {
                request.extensions_mut().insert(principal);
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                Box::pin(inner.call(request))
            }
            Err(status) => {
                tracing::debug!(path = request.uri().path(), code = ?status.code(), "request refused");
                Box::pin(std::future::ready(Ok(status.into_http())))
            }
        }
    }
}
