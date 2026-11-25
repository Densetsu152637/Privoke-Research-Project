//! What the pool needs to know about the protocol above the frames.

/// The first frame a worker sends, as the protocol understands it.
#[derive(Debug)]
pub enum Hello<I> {
    /// The worker has finished loading and serves requests. `I` is its announcement, kept for diagnostics.
    Ready(I),
    /// The worker refused to run (for example a failed bundle check). The slot stops for good: no restart.
    Fatal(String),
}

/// A worker's answer to one request.
#[derive(Debug)]
pub enum Reply {
    /// The request succeeded; the result is handed to the caller as text.
    Answer(String),
    /// The worker answered with an error of its own and stays up.
    Reported(String),
    /// The frame was malformed or answered a different request. The worker is killed and restarted.
    Violation(String),
}

/// The protocol on top of the frames. The pool owns processes, queueing and deadlines; the protocol owns meaning.
pub trait Protocol: Send + Sync + 'static {
    /// What a ready worker announces.
    type Info: Clone + Send + Sync + 'static;

    /// Interprets the first frame. `Err` is a malformed or unexpected frame; the worker is restarted with backoff.
    fn parse_hello(&self, frame: &[u8]) -> Result<Hello<Self::Info>, String>;

    /// Interprets the answer to the request numbered `request_id`.
    fn parse_reply(&self, frame: &[u8], request_id: u64) -> Reply;
}
