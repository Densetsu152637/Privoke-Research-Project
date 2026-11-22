//! The gRPC shell of the cycle engine: `V3FuzzerService` over [`Engine`].

use std::sync::Arc;

use privoke_contracts::proto::experimental_v3::v3_fuzzer_service_server::V3FuzzerService;
use privoke_contracts::proto::experimental_v3::{HealthRequest, HealthResponse, Scope};
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use tonic::{Request, Response, Status};

use crate::cycle::Engine;

/// The `V3FuzzerService` implementation.
#[derive(Debug, Clone)]
pub struct V3Handler {
    engine: Arc<Engine>,
}

impl V3Handler {
    /// A handler over `engine`.
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }
}

#[tonic::async_trait]
impl V3FuzzerService for V3Handler {
    async fn run_training_cycle(&self, request: Request<FuzzerTrainingRequest>) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.engine.run(request.into_inner(), Scope::Heads).await.map(Response::new)
    }

    async fn run_underlying_training_cycle(
        &self,
        request: Request<FuzzerTrainingRequest>,
    ) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.engine.run(request.into_inner(), Scope::FullEncoder).await.map(Response::new)
    }

    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        self.engine.health().map(Response::new)
    }
}
