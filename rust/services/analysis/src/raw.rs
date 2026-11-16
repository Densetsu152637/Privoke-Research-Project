//! The gRPC surface: `privoke.v1.PrivokeRuntimeService`, served over a pass-through codec.
//!
//! The worker serialises each response with deterministic map order, exactly as the gRPC server it replaces does. Decoding
//! that into a Rust message and encoding it again is not byte-faithful: `prost` leaves a map entry's value out when it is
//! the default (a `0.0` metric, an empty metadata value), where the Python serialiser writes it. So this service never
//! rebuilds a response. [`RawCodec`] hands the request bytes to [`crate::service`] untouched (after it read them to
//! decide whether to serve them) and writes the worker's response bytes to the wire as they came.
//!
//! The server is the shape `tonic-build` generates for `PrivokeRuntimeServiceServer`, with the prost codec replaced.

use bytes::{Buf, BufMut};
use tonic::Status;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::codegen::{Body, BoxFuture, Context, Poll, Service, StdError, http};

use crate::service::{AnalysisService, Rpc};

/// A codec whose messages are the serialized protobuf bytes themselves.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawCodec;

/// Writes the bytes of a message as they are.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawEncoder;

/// Reads the bytes of a message as they are.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawDecoder;

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for RawDecoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        let mut bytes = vec![0u8; src.remaining()];
        src.copy_to_slice(&mut bytes);
        Ok(Some(bytes))
    }
}

impl Codec for RawCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder;

    fn encoder(&mut self) -> RawEncoder {
        RawEncoder
    }

    fn decoder(&mut self) -> RawDecoder {
        RawDecoder
    }
}

/// The gRPC service name.
pub const SERVICE_NAME: &str = "privoke.v1.PrivokeRuntimeService";

/// The `PrivokeRuntimeService` server over [`AnalysisService`].
#[derive(Debug, Clone)]
pub struct RuntimeServer {
    service: AnalysisService,
    max_decoding_message_size: usize,
}

impl RuntimeServer {
    /// Serve `service`, refusing request messages above `max_decoding_message_size` bytes.
    pub fn new(service: AnalysisService, max_decoding_message_size: usize) -> Self {
        Self { service, max_decoding_message_size }
    }
}

impl tonic::server::NamedService for RuntimeServer {
    const NAME: &'static str = SERVICE_NAME;
}

struct Call {
    service: AnalysisService,
    rpc: Rpc,
}

impl tonic::server::UnaryService<Vec<u8>> for Call {
    type Response = Vec<u8>;
    type Future = BoxFuture<tonic::Response<Vec<u8>>, Status>;

    fn call(&mut self, request: tonic::Request<Vec<u8>>) -> Self::Future {
        let service = self.service.clone();
        let rpc = self.rpc;
        Box::pin(async move { service.handle(rpc, request).await })
    }
}

impl<B> Service<http::Request<B>> for RuntimeServer
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let Some(rpc) = Rpc::from_path(request.uri().path()) else {
            return Box::pin(async move {
                let mut response = http::Response::new(tonic::body::Body::default());
                response.headers_mut().insert("grpc-status", (tonic::Code::Unimplemented as i32).into());
                response.headers_mut().insert("content-type", http::HeaderValue::from_static("application/grpc"));
                Ok(response)
            });
        };
        let call = Call { service: self.service.clone(), rpc };
        let limit = self.max_decoding_message_size;
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(RawCodec).apply_max_message_size_config(Some(limit), None);
            Ok(grpc.unary(call, request).await)
        })
    }
}
