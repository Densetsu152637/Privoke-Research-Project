//! The gRPC shell of the cycle engine: `FuzzerService` over [`Engine`](crate::cycle::Engine).

use std::sync::Arc;

use privoke_contracts::proto::v1::fuzzer_service_server::FuzzerService;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse, HealthRequest, HealthResponse};
use tonic::{Request, Response, Status};

use crate::SERVICE_NAME;
use crate::config::Scope;
use crate::cycle::Engine;

/// The `FuzzerService` implementation.
#[derive(Debug, Clone)]
pub struct FuzzerHandler {
    engine: Arc<Engine>,
}

impl FuzzerHandler {
    /// A handler over `engine`.
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }
}

#[tonic::async_trait]
impl FuzzerService for FuzzerHandler {
    async fn run_training_cycle(&self, request: Request<FuzzerTrainingRequest>) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.engine.run_training_cycle(request.into_inner(), Scope::Heads).await.map(Response::new)
    }

    async fn run_underlying_training_cycle(
        &self,
        request: Request<FuzzerTrainingRequest>,
    ) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.engine.run_training_cycle(request.into_inner(), Scope::FullEncoder).await.map(Response::new)
    }

    async fn run_presence_training_cycle(
        &self,
        request: Request<FuzzerTrainingRequest>,
    ) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.engine.run_presence_cycle(request.into_inner()).await.map(Response::new)
    }

    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse { service: SERVICE_NAME.to_string(), status: "SERVING".to_string() }))
    }
}
