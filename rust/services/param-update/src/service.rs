//! The gRPC handlers.
//!
//! Authorisation has already happened in `privoke-transport`'s layer: only a `publisher` or `trainer` reaches
//! `GetParameterUpdateStatus`. `SubmitParameterUpdate` was removed in stage V3-R8b (`UNIMPLEMENTED`). What is left here is
//! identity binding: a non-empty `source_id` claim of the status RPC must be the caller's own service name (or URN).
//!
//! The engine does blocking file and SQLite work, so each call runs on the blocking pool.

use std::sync::Arc;

use privoke_contracts::proto::v1::param_update_service_server::ParamUpdateService;
use privoke_contracts::proto::v1::{
    HealthRequest, HealthResponse, ParameterUpdateAck, ParameterUpdateRequest, ParameterUpdateStatus, ParameterUpdateStatusRequest,
};
use privoke_transport::Principal;
use tonic::{Request, Response, Status};

use crate::engine::Engine;
use crate::util::log;

/// The handlers over a shared engine.
#[derive(Debug, Clone)]
pub struct ParamUpdateHandler {
    engine: Arc<Engine>,
}

impl ParamUpdateHandler {
    /// Handlers over `engine`.
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }
}

fn caller<T>(request: &Request<T>) -> Result<Principal, Status> {
    request.extensions().get::<Principal>().cloned().ok_or_else(|| Status::unauthenticated("connection carries no authorised principal"))
}

#[tonic::async_trait]
impl ParamUpdateService for ParamUpdateHandler {
    /// Removed in stage V3-R8b: V1 models are served for detection and no longer trained. The transport policy does not list
    /// the path either, so this is only reached by a caller that bypasses it.
    async fn submit_parameter_update(&self, _request: Request<ParameterUpdateRequest>) -> Result<Response<ParameterUpdateAck>, Status> {
        Err(Status::unimplemented("SubmitParameterUpdate was removed: V1 models are not trained."))
    }

    async fn get_parameter_update_status(
        &self,
        request: Request<ParameterUpdateStatusRequest>,
    ) -> Result<Response<ParameterUpdateStatus>, Status> {
        let principal = caller(&request)?;
        let message = request.into_inner();
        principal.check_claim(&message.source_id)?;
        let engine = self.engine.clone();
        match tokio::task::spawn_blocking(move || engine.status(&message)).await {
            Ok(Ok(status)) => Ok(Response::new(status)),
            Ok(Err(failure)) => Err(failure.to_status()),
            Err(error) => {
                log(format_args!("update status task failed: {error}"));
                Err(Status::internal(crate::error::LOOKUP_FAILED))
            }
        }
    }

    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        let engine = self.engine.clone();
        match tokio::task::spawn_blocking(move || engine.health()).await {
            Ok(response) => Ok(Response::new(response)),
            Err(error) => {
                log(format_args!("health task failed: {error}"));
                Err(Status::internal("Health check failed."))
            }
        }
    }
}
