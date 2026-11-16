//! The worker protocol: length-prefixed JSON frames, and the typed requests and results they carry.
//!
//! A frame is a 4-byte little-endian length followed by that many bytes of UTF-8 JSON. The client writes requests to
//! the worker's stdin. The worker writes frames to a dedicated descriptor that is a duplicate of its original stdout;
//! afterwards its own fd 1 is pointed at stderr, so a stray `print` or C-library message cannot corrupt a frame.
//!
//! ```text
//! worker -> client, once:  {"type":"ready","protocol":1,"spacy":"3.7.5","model":"en_core_web_sm","model_version":"3.7.1",...}
//!                     or:  {"type":"fatal","reason":"..."}          (bundle refused; the worker then exits)
//! client -> worker:        {"id":7,"op":"analyze","selection":"full"|"tagger","text":"..."}
//!                          {"id":8,"op":"lemma_index"}
//! worker -> client:        {"id":7,"ok":true,"result":<json>}  or  {"id":7,"ok":false,"error":"..."}
//! ```
//!
//! The `analyze` result is `{"tokens":[[text,idx,whitespace,is_alpha,lower,tag,pos,lemma,dep,head],...],
//! "ents":[[start_char,end_char,label],...]}`: one array per token, in the field order of the stage 11 plan. `idx`,
//! `start_char` and `end_char` are code-point offsets. The result bytes are produced by one function that both the
//! worker and the reference environment run, which is what the parity gate compares.

use std::io;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::SpacyError;
use crate::offsets::{OffsetMap, Span};

/// The protocol revision announced in the ready frame.
pub const PROTOCOL_VERSION: u32 = 1;

/// The largest frame either side accepts. A 20 000 character document is far below it.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Which part of the spaCy pipeline runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
pub enum Selection {
    /// The whole pipeline, including `ner`: tokens, attributes and entities.
    #[serde(rename = "full")]
    Full,
    /// The post-filter's sub-pipeline: `tok2vec`, `tagger`, `attribute_ruler` and `lemmatizer`. It has no entities.
    #[serde(rename = "tagger")]
    TaggerOnly,
}

impl Selection {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::TaggerOnly => "tagger",
        }
    }
}

/// A request frame.
#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request<'a> {
    /// Run spaCy on a text.
    Analyze {
        /// Correlates the answer.
        id: u64,
        /// Pipeline selection.
        selection: Selection,
        /// The text.
        text: &'a str,
    },
    /// The model's lemma-index word list (once per process).
    LemmaIndex {
        /// Correlates the answer.
        id: u64,
    },
    /// Test hook: the worker crashes without answering. Honoured only by workers built with `test-hooks`.
    TestCrash {
        /// Correlates the answer.
        id: u64,
    },
    /// Test hook: the worker prints on stdout (Python and C level) and then answers normally.
    TestPrint {
        /// Correlates the answer.
        id: u64,
    },
    /// Test hook: the worker sleeps, then answers.
    TestSleep {
        /// Correlates the answer.
        id: u64,
        /// Milliseconds to sleep.
        ms: u64,
    },
}

impl Request<'_> {
    /// The request's id.
    pub fn id(&self) -> u64 {
        match self {
            Self::Analyze { id, .. }
            | Self::LemmaIndex { id }
            | Self::TestCrash { id }
            | Self::TestPrint { id }
            | Self::TestSleep { id, .. } => *id,
        }
    }

    /// The frame payload.
    pub fn encode(&self) -> Result<Vec<u8>, SpacyError> {
        serde_json::to_vec(self).map_err(|e| SpacyError::Protocol(format!("cannot encode a request: {e}")))
    }
}

/// The first frame a worker sends.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct WorkerInfo {
    /// `ready` or `fatal`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The refusal reason for a `fatal` frame.
    #[serde(default)]
    pub reason: Option<String>,
    /// The protocol revision.
    #[serde(default)]
    pub protocol: Option<u32>,
    /// The spaCy version.
    #[serde(default)]
    pub spacy: Option<String>,
    /// The loaded model's name.
    #[serde(default)]
    pub model: Option<String>,
    /// The loaded model's version.
    #[serde(default)]
    pub model_version: Option<String>,
    /// The CPython version string.
    #[serde(default)]
    pub python: Option<String>,
    /// SHA-256 of the `bundle.lock.txt` the worker checked itself against.
    #[serde(default)]
    pub lock_sha256: Option<String>,
}

/// A response frame whose result is kept as the exact bytes the worker produced.
#[derive(Debug, Deserialize)]
pub(crate) struct Envelope<'a> {
    pub id: u64,
    pub ok: bool,
    #[serde(borrow, default)]
    pub result: Option<&'a RawValue>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Writes one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(out: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    out.write_all(&len.to_le_bytes()).await?;
    out.write_all(payload).await?;
    out.flush().await
}

/// Reads one frame. A clean end of stream before the length is `UnexpectedEof`.
pub async fn read_frame<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame of {len} bytes exceeds the limit")));
    }
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload).await?;
    Ok(payload)
}

/// One spaCy token. The offsets of [`Token::span`] come from the code-point index the worker reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    /// `token.text`.
    pub text: String,
    /// `token.idx` in code points.
    pub idx: usize,
    /// `token.whitespace_`.
    pub whitespace: String,
    /// `token.is_alpha`.
    pub is_alpha: bool,
    /// `token.lower_`.
    pub lower: String,
    /// `token.tag_`.
    pub tag: String,
    /// `token.pos_`.
    pub pos: String,
    /// `token.lemma_`.
    pub lemma: String,
    /// `token.dep_`.
    pub dep: String,
    /// `token.head.i`, the index of the head token.
    pub head: usize,
    /// The token's range in code points, bytes and UTF-16 units.
    pub span: Span,
}

/// One named entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entity {
    /// `ent.label_`.
    pub label: String,
    /// The entity's range in code points, bytes and UTF-16 units.
    pub span: Span,
}

/// A decoded `analyze` result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Analysis {
    /// Tokens in document order.
    pub tokens: Vec<Token>,
    /// Entities in document order. Empty for [`Selection::TaggerOnly`].
    pub entities: Vec<Entity>,
}

type WireToken = (String, usize, String, bool, String, String, String, String, String, usize);
type WireEntity = (usize, usize, String);

#[derive(Deserialize)]
struct WireAnalysis {
    tokens: Vec<WireToken>,
    ents: Vec<WireEntity>,
}

/// The exact JSON text of an `analyze` result, as the worker produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawAnalysis {
    body: String,
}

impl RawAnalysis {
    pub(crate) fn new(body: String) -> Self {
        Self { body }
    }

    /// The result bytes. The parity gate hashes these.
    pub fn as_str(&self) -> &str {
        &self.body
    }

    /// Decodes the result against the text that was sent, converting code-point offsets to UTF-8 and UTF-16 offsets.
    /// Every token and entity is checked against the text, so a worker that disagrees about the text is an error.
    pub fn decode(&self, text: &str) -> Result<Analysis, SpacyError> {
        let wire: WireAnalysis =
            serde_json::from_str(&self.body).map_err(|e| SpacyError::Protocol(format!("malformed analyze result: {e}")))?;
        let map = OffsetMap::new(text);
        let bad = |what: &str, start: usize| SpacyError::Protocol(format!("{what} at code point {start} does not match the text"));
        let mut tokens = Vec::with_capacity(wire.tokens.len());
        for (text_, idx, whitespace, is_alpha, lower, tag, pos, lemma, dep, head) in wire.tokens {
            let end = idx + text_.chars().count();
            let span = map.span(idx, end).ok_or_else(|| bad("token", idx))?;
            if text.get(span.bytes()) != Some(text_.as_str()) {
                return Err(bad("token", idx));
            }
            tokens.push(Token { text: text_, idx, whitespace, is_alpha, lower, tag, pos, lemma, dep, head, span });
        }
        let mut entities = Vec::with_capacity(wire.ents.len());
        for (start, end, label) in wire.ents {
            let span = map.span(start, end).ok_or_else(|| bad("entity", start))?;
            entities.push(Entity { label, span });
        }
        Ok(Analysis { tokens, entities })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, b"{\"x\":1}").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), b"{\"x\":1}");
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_is_unexpected_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_le_bytes()).await.unwrap();
        a.write_all(b"abc").await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn analyze_request_encoding_is_stable() {
        let request = Request::Analyze { id: 7, selection: Selection::TaggerOnly, text: "a\"b" };
        assert_eq!(request.encode().unwrap(), br#"{"op":"analyze","id":7,"selection":"tagger","text":"a\"b"}"#);
        assert_eq!(Request::LemmaIndex { id: 8 }.encode().unwrap(), br#"{"op":"lemma_index","id":8}"#);
    }

    #[test]
    fn decode_converts_offsets_and_checks_the_text() {
        let text = "a\u{1F600} b";
        let body = r#"{"tokens":[["a😀",0," ",false,"a😀","NN","NOUN","a","ROOT",0],["b",3,"",true,"b","NN","NOUN","b","dep",0]],"ents":[[3,4,"ORG"]]}"#;
        let analysis = RawAnalysis::new(body.to_string()).decode(text).unwrap();
        assert_eq!(analysis.tokens[0].span.end_byte, 5);
        assert_eq!(analysis.tokens[0].span.end_utf16, 3);
        assert_eq!(analysis.tokens[1].span.start_byte, 6);
        assert_eq!(analysis.tokens[1].span.start_utf16, 4);
        assert_eq!(analysis.entities[0].label, "ORG");
        assert_eq!(&text[analysis.entities[0].span.bytes()], "b");
        // A token that does not match the text is a protocol error, not a silently wrong span.
        let err = RawAnalysis::new(body.to_string()).decode("zz zz").unwrap_err();
        assert!(matches!(err, SpacyError::Protocol(_)));
    }
}
