//! The worker's request loop, independent of Python so that it can be tested without an interpreter.
//!
//! [`serve`] reads length-prefixed JSON requests from `input` and writes answers to `output`. The binary passes the
//! process's stdin and a duplicate of its original stdout as those two ends, and a PyO3-backed [`Handler`]. See
//! `privoke_spacy::protocol` for the frame and message formats.

use std::io::{self, Read, Write};

use privoke_spacy::protocol::MAX_FRAME_BYTES;
use serde::Deserialize;

/// What the worker does with a request. Each method returns the JSON text of the result, or an error message that is
/// reported to the client without stopping the worker.
pub trait Handler {
    /// Runs spaCy: `selection` is `full` or `tagger`.
    fn analyze(&mut self, selection: &str, text: &str) -> Result<String, String>;
    /// The lemma-index word list as a JSON array.
    fn lemma_index(&mut self) -> Result<String, String>;
    /// Test hook: prints on stdout from Python and from C-level `write(1, ...)`, then answers `null`.
    #[cfg(feature = "test-hooks")]
    fn test_print(&mut self) -> Result<String, String>;
}

#[derive(Deserialize)]
struct Request {
    id: u64,
    op: String,
    #[serde(default)]
    selection: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[cfg_attr(not(feature = "test-hooks"), allow(dead_code))]
    #[serde(default)]
    ms: Option<u64>,
}

/// Reads one frame. `None` is a clean end of input at a frame boundary.
pub fn read_frame(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request frame exceeds the limit"));
    }
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Writes one frame as a single write, so a partial frame can only come from a dying process.
pub fn write_frame(output: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    output.write_all(&buf)?;
    output.flush()
}

fn reply(id: u64, outcome: Result<String, String>) -> Vec<u8> {
    match outcome {
        Ok(body) => format!(r#"{{"id":{id},"ok":true,"result":{body}}}"#).into_bytes(),
        Err(message) => {
            let quoted = serde_json::to_string(&message).unwrap_or_else(|_| "\"error\"".to_string());
            format!(r#"{{"id":{id},"ok":false,"error":{quoted}}}"#).into_bytes()
        }
    }
}

/// Serves requests until the client closes its end. A frame that is not a valid request ends the loop with an error,
/// because the client's view of the stream is then unknown; the pool replaces the process.
pub fn serve(input: &mut impl Read, output: &mut impl Write, handler: &mut impl Handler) -> io::Result<()> {
    while let Some(frame) = read_frame(input)? {
        let request: Request =
            serde_json::from_slice(&frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("malformed request: {e}")))?;
        let outcome = match request.op.as_str() {
            "analyze" => match (request.selection.as_deref(), request.text.as_deref()) {
                (Some(selection @ ("full" | "tagger")), Some(text)) => handler.analyze(selection, text),
                _ => Err("analyze needs a selection of full or tagger, and a text".to_string()),
            },
            "lemma_index" => handler.lemma_index(),
            #[cfg(feature = "test-hooks")]
            "test_crash" => std::process::exit(86),
            #[cfg(feature = "test-hooks")]
            "test_print" => handler.test_print(),
            #[cfg(feature = "test-hooks")]
            "test_sleep" => {
                std::thread::sleep(std::time::Duration::from_millis(request.ms.unwrap_or(0)));
                Ok("null".to_string())
            }
            other => Err(format!("unknown op {other:?}")),
        };
        write_frame(output, &reply(request.id, outcome))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct Echo;

    impl Handler for Echo {
        fn analyze(&mut self, selection: &str, text: &str) -> Result<String, String> {
            if text == "boom" { Err("exploded".into()) } else { Ok(format!(r#"{{"selection":"{selection}","n":{}}}"#, text.len())) }
        }
        fn lemma_index(&mut self) -> Result<String, String> {
            Ok(r#"["a","b"]"#.into())
        }
        #[cfg(feature = "test-hooks")]
        fn test_print(&mut self) -> Result<String, String> {
            Ok("null".into())
        }
    }

    fn frames(requests: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in requests {
            write_frame(&mut out, r.as_bytes()).unwrap();
        }
        out
    }

    fn answers(mut bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(frame) = read_frame(&mut bytes).unwrap() {
            out.push(String::from_utf8(frame).unwrap());
        }
        out
    }

    #[test]
    fn answers_each_request_with_its_id_and_the_raw_result() {
        let input = frames(&[
            r#"{"id":1,"op":"analyze","selection":"full","text":"hello"}"#,
            r#"{"id":2,"op":"lemma_index"}"#,
            r#"{"id":3,"op":"analyze","selection":"tagger","text":"boom"}"#,
            r#"{"id":4,"op":"analyze","selection":"other","text":"x"}"#,
            r#"{"id":5,"op":"nope"}"#,
        ]);
        let mut output = Vec::new();
        serve(&mut input.as_slice(), &mut output, &mut Echo).unwrap();
        assert_eq!(
            answers(&output),
            [
                r#"{"id":1,"ok":true,"result":{"selection":"full","n":5}}"#,
                r#"{"id":2,"ok":true,"result":["a","b"]}"#,
                r#"{"id":3,"ok":false,"error":"exploded"}"#,
                r#"{"id":4,"ok":false,"error":"analyze needs a selection of full or tagger, and a text"}"#,
                r#"{"id":5,"ok":false,"error":"unknown op \"nope\""}"#,
            ]
        );
    }

    #[test]
    fn a_malformed_request_ends_the_loop_with_an_error() {
        let input = frames(&["not json"]);
        let err = serve(&mut input.as_slice(), &mut Vec::new(), &mut Echo).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn end_of_input_between_frames_is_a_clean_exit() {
        assert!(serve(&mut [].as_slice(), &mut Vec::new(), &mut Echo).is_ok());
    }

    #[test]
    fn a_truncated_frame_is_an_error() {
        let mut input = frames(&[r#"{"id":1,"op":"lemma_index"}"#]);
        input.truncate(input.len() - 3);
        assert!(serve(&mut input.as_slice(), &mut Vec::new(), &mut Echo).is_err());
    }
}
