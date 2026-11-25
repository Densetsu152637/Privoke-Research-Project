//! The gRPC handlers (`server.py`'s `TelemetryCollector`).
//!
//! `RecordTelemetry` validates, takes a slot from the per-source daily cap, and adds the report to the aggregates.
//! The handler reads the connection's source address for the cap and nothing else about the peer: the certificate
//! identity is the shared reporter credential, carries no information, and is neither stored nor logged.

use std::net::IpAddr;
use std::sync::Arc;

use privoke_contracts::proto::v1::telemetry_service_server::TelemetryService;
use privoke_contracts::proto::v1::{
    GetTelemetrySummaryRequest, GetTelemetrySummaryResponse, RecordTelemetryResponse, TelemetryCategoryEstimate,
    TelemetryDimensionEstimate, TelemetryHealthRequest, TelemetryHealthResponse, TelemetryPacket,
};
use privoke_transport::ConnectionInfo;
use tonic::{Request, Response, Status};

use crate::SERVICE_NAME;
use crate::daily::DailyCap;
use crate::storage::{Summary, TelemetryStore};
use crate::util::log;
use crate::validation::validate_telemetry_packet;

const ACCEPTED_MESSAGE: &str = "Protected report added to aggregates.";

/// The collector: a store and the daily cap. Cloning shares both.
#[derive(Debug, Clone)]
pub struct TelemetryCollector {
    store: Arc<TelemetryStore>,
    cap: DailyCap,
}

impl TelemetryCollector {
    /// A collector over `store` with the per-source daily `cap`.
    pub fn new(store: TelemetryStore, cap: DailyCap) -> Self {
        Self { store: Arc::new(store), cap }
    }
}

/// The source address of the connection, used only as the daily-cap key. A request without one (which the
/// authorisation layer already refuses) shares the unspecified address, so it can never escape the cap.
fn source_address<T>(request: &Request<T>) -> IpAddr {
    request.extensions().get::<ConnectionInfo>().and_then(|info| info.peer_addr).map_or(IpAddr::from([0, 0, 0, 0]), |address| address.ip())
}

fn into_response(summary: Summary) -> GetTelemetrySummaryResponse {
    GetTelemetrySummaryResponse {
        sample_count: summary.sample_count,
        dimensions: summary
            .dimensions
            .into_iter()
            .map(|dimension| TelemetryDimensionEstimate {
                dimension: dimension.dimension.to_string(),
                values: dimension
                    .values
                    .into_iter()
                    .map(|item| TelemetryCategoryEstimate {
                        value: item.value.to_string(),
                        estimated_count: item.estimated_count,
                        observed_noisy_count: item.observed_noisy_count,
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[tonic::async_trait]
impl TelemetryService for TelemetryCollector {
    async fn record_telemetry(&self, request: Request<TelemetryPacket>) -> Result<Response<RecordTelemetryResponse>, Status> {
        let source = source_address(&request);
        let packet = request.into_inner();
        validate_telemetry_packet(&packet).map_err(Status::invalid_argument)?;
        let reservation = self.cap.reserve(source)?;
        let store = self.store.clone();
        let stored = tokio::task::spawn_blocking(move || store.record(&packet)).await;
        match stored {
            Ok(Ok(())) => {
                reservation.commit();
                Ok(Response::new(RecordTelemetryResponse { accepted: true, message: ACCEPTED_MESSAGE.to_string() }))
            }
            Ok(Err(error)) => {
                log(format_args!("telemetry persistence failed: {error}"));
                Err(Status::internal("Telemetry persistence failed."))
            }
            Err(error) => {
                log(format_args!("telemetry persistence task failed: {error}"));
                Err(Status::internal("Telemetry persistence failed."))
            }
        }
    }

    async fn get_telemetry_summary(
        &self,
        _request: Request<GetTelemetrySummaryRequest>,
    ) -> Result<Response<GetTelemetrySummaryResponse>, Status> {
        let store = self.store.clone();
        match tokio::task::spawn_blocking(move || store.summary()).await {
            Ok(Ok(summary)) => Ok(Response::new(into_response(summary))),
            Ok(Err(error)) => {
                log(format_args!("telemetry aggregation failed: {error}"));
                Err(Status::internal("Telemetry aggregation failed."))
            }
            Err(error) => {
                log(format_args!("telemetry aggregation task failed: {error}"));
                Err(Status::internal("Telemetry aggregation failed."))
            }
        }
    }

    async fn health(&self, _request: Request<TelemetryHealthRequest>) -> Result<Response<TelemetryHealthResponse>, Status> {
        let store = self.store.clone();
        let writable = tokio::task::spawn_blocking(move || store.check_writable()).await.is_ok_and(|result| result.is_ok());
        let status = if writable { "SERVING" } else { "NOT_SERVING" };
        Ok(Response::new(TelemetryHealthResponse { service: SERVICE_NAME.to_string(), status: status.to_string() }))
    }
}
