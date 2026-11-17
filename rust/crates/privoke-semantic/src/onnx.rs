//! The weights of the pinned contextual encoder, read from its ONNX export without running the graph.
//!
//! The contextual encoder of the Python runtime (`privoke-pretrained-context-minilm`) runs `model.onnx` in
//! onnxruntime. That file is the plain PyTorch export of a Hugging Face `BertModel` (`last_hidden_state` only), and the
//! runtime admits it by its SHA-256, so its graph is the audited one. This reader does not interpret the graph: it takes
//! the constants out of it by name, and the encoder of [`crate::bert`] runs the same computation.
//!
//! The export names every constant after the Hugging Face tensor it came from, with one exception: the weight of each
//! `MatMul` is an anonymous `onnx::MatMul_N` initializer, stored `[input][output]`. Such a weight is named by the
//! `MatMul` node that consumes it (`/encoder/layer.3/attention/self/query/MatMul`) and becomes the Hugging Face tensor
//! `encoder.layer.3.attention.self.query.weight`, transposed to `[output][input]`. Anything that does not fit this
//! pattern (an initializer that no `MatMul` names and no Hugging Face name explains, a `MatMul` weight that is not a
//! float32 matrix, external data, a duplicate name) is refused: nothing is guessed.
//!
//! Only a hand-written subset of the ONNX protobuf is decoded: `ModelProto.graph` (field 7), `GraphProto.node` (1) and
//! `.initializer` (5), `NodeProto.input` (1), `.name` (3) and `.op_type` (4), and `TensorProto.dims` (1), `.data_type`
//! (2), `.name` (8), `.raw_data` (9) and `.data_location` (14).

use std::collections::BTreeMap;

use privoke_contracts::digest::sha256_hex;

use crate::error::SemanticError;
use crate::safetensors::Tensor;

/// `TensorProto.DataType.FLOAT`.
const FLOAT: u64 = 1;
/// Largest model file read (the pinned export is about 90 MB).
pub const MAX_ONNX_BYTES: usize = 100 * 1024 * 1024;
/// The `MatMul` nodes of one encoder layer and the Hugging Face tensor each one's weight is.
const LAYER_MATMULS: [(&str, &str); 6] = [
    ("attention/self/query", "attention.self.query"),
    ("attention/self/key", "attention.self.key"),
    ("attention/self/value", "attention.self.value"),
    ("attention/output/dense", "attention.output.dense"),
    ("intermediate/dense", "intermediate.dense"),
    ("output/dense", "output.dense"),
];

fn refuse(message: impl Into<String>) -> SemanticError {
    SemanticError::artifact(format!("Pretrained contextual ONNX export is not the admitted graph: {}", message.into()))
}

/// One decoded protobuf field.
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// A fixed-width field, which this subset never needs.
    Fixed,
}

fn read_varint(bytes: &[u8], at: &mut usize) -> Result<u64, SemanticError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*at).ok_or_else(|| refuse("truncated varint"))?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(refuse("varint is too long"))
}

/// The fields of one message, in order.
fn fields(bytes: &[u8]) -> Result<Vec<(u64, Value<'_>)>, SemanticError> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let key = read_varint(bytes, &mut at)?;
        let (number, wire) = (key >> 3, key & 7);
        let value = match wire {
            0 => Value::Varint(read_varint(bytes, &mut at)?),
            2 => {
                let length = usize::try_from(read_varint(bytes, &mut at)?).map_err(|_| refuse("field length"))?;
                let end = at.checked_add(length).filter(|end| *end <= bytes.len()).ok_or_else(|| refuse("field runs past its message"))?;
                let slice = bytes.get(at..end).ok_or_else(|| refuse("field runs past its message"))?;
                at = end;
                Value::Bytes(slice)
            }
            1 | 5 => {
                let width = if wire == 1 { 8 } else { 4 };
                at = at.checked_add(width).filter(|end| *end <= bytes.len()).ok_or_else(|| refuse("fixed field runs past its message"))?;
                Value::Fixed
            }
            other => return Err(refuse(format!("unsupported wire type {other}"))),
        };
        out.push((number, value));
    }
    Ok(out)
}

fn text(bytes: &[u8]) -> Result<String, SemanticError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| refuse("a name is not UTF-8"))
}

struct Node {
    name: String,
    op: String,
    inputs: Vec<String>,
}

fn parse_node(bytes: &[u8]) -> Result<Node, SemanticError> {
    let (mut name, mut op, mut inputs) = (String::new(), String::new(), Vec::new());
    for (number, value) in fields(bytes)? {
        match (number, value) {
            (1, Value::Bytes(input)) => inputs.push(text(input)?),
            (3, Value::Bytes(value)) => name = text(value)?,
            (4, Value::Bytes(value)) => op = text(value)?,
            _ => {}
        }
    }
    Ok(Node { name, op, inputs })
}

struct Initializer {
    shape: Vec<usize>,
    data: Vec<f32>,
    sha256: String,
}

fn parse_tensor(bytes: &[u8]) -> Result<(String, Initializer), SemanticError> {
    let (mut name, mut data_type, mut raw) = (String::new(), None, None);
    let mut dims: Vec<u64> = Vec::new();
    for (number, value) in fields(bytes)? {
        match (number, value) {
            (1, Value::Varint(dim)) => dims.push(dim),
            (1, Value::Bytes(packed)) => {
                let mut at = 0usize;
                while at < packed.len() {
                    dims.push(read_varint(packed, &mut at)?);
                }
            }
            (2, Value::Varint(kind)) => data_type = Some(kind),
            (8, Value::Bytes(value)) => name = text(value)?,
            (9, Value::Bytes(value)) => raw = Some(value),
            (14, Value::Varint(location)) if location != 0 => return Err(refuse(format!("{name} keeps its data outside the file"))),
            _ => {}
        }
    }
    if name.is_empty() {
        return Err(refuse("an initializer has no name"));
    }
    if data_type != Some(FLOAT) {
        return Err(refuse(format!("{name} is not a float32 tensor")));
    }
    let raw = raw.ok_or_else(|| refuse(format!("{name} has no raw data")))?;
    let shape: Vec<usize> =
        dims.iter().map(|dim| usize::try_from(*dim).map_err(|_| refuse("a dimension is too large"))).collect::<Result<_, _>>()?;
    let count = shape.iter().try_fold(1usize, |product, dim| product.checked_mul(*dim)).ok_or_else(|| refuse("a tensor is too large"))?;
    if raw.len() != count.checked_mul(4).ok_or_else(|| refuse("a tensor is too large"))? {
        return Err(refuse(format!("{name} holds {} bytes for {count} values", raw.len())));
    }
    let data: Vec<f32> = raw.chunks_exact(4).map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])).collect();
    if data.iter().any(|value| !value.is_finite()) {
        return Err(refuse(format!("{name} holds a value that is not finite")));
    }
    Ok((name, Initializer { shape, data, sha256: sha256_hex(raw) }))
}

/// `[input][output]` to `[output][input]`.
fn transpose(weight: &Initializer, name: &str) -> Result<Tensor, SemanticError> {
    let [input, output] = weight.shape[..] else {
        return Err(refuse(format!("the weight {name} is not a matrix")));
    };
    let mut data = vec![0f32; weight.data.len()];
    for (row, values) in weight.data.chunks(output).enumerate() {
        for (column, value) in values.iter().enumerate() {
            data[column * input + row] = *value;
        }
    }
    Ok(Tensor { shape: vec![output, input], data, sha256: weight.sha256.clone() })
}

/// The `[layer, part]` of a `MatMul` node name `/encoder/layer.<layer>/<part>/MatMul` whose part is one of the six
/// matrix products of a layer; `None` for every other node.
fn layer_matmul(node: &str) -> Option<(usize, &'static str)> {
    let rest = node.strip_prefix("/encoder/layer.")?;
    let (index, path) = rest.split_once('/')?;
    let part = path.strip_suffix("/MatMul")?;
    LAYER_MATMULS.iter().find(|(from, _)| *from == part).and_then(|(_, to)| Some((index.parse().ok()?, *to)))
}

/// The tensors of an encoder export, under their Hugging Face names (`embeddings.word_embeddings.weight`,
/// `encoder.layer.0.attention.self.query.weight` as `[output][input]`, and so on), for `layers` encoder layers.
///
/// Every initializer must be explained: a Hugging Face name of the embeddings or of a layer below `layers`, or the weight
/// of one of the six `MatMul` nodes of such a layer.
pub fn encoder_tensors(bytes: &[u8], layers: usize) -> Result<BTreeMap<String, Tensor>, SemanticError> {
    if bytes.len() > MAX_ONNX_BYTES {
        return Err(refuse("the file is larger than 100 MiB"));
    }
    let graph = fields(bytes)?
        .into_iter()
        .find_map(|(number, value)| match (number, value) {
            (7, Value::Bytes(graph)) => Some(graph),
            _ => None,
        })
        .ok_or_else(|| refuse("the model has no graph"))?;
    let (mut nodes, mut initializers): (Vec<Node>, BTreeMap<String, Initializer>) = (Vec::new(), BTreeMap::new());
    for (number, value) in fields(graph)? {
        match (number, value) {
            (1, Value::Bytes(node)) => nodes.push(parse_node(node)?),
            (5, Value::Bytes(tensor)) => {
                let (name, initializer) = parse_tensor(tensor)?;
                if initializers.insert(name.clone(), initializer).is_some() {
                    return Err(refuse(format!("the initializer {name} appears twice")));
                }
            }
            _ => {}
        }
    }

    let mut tensors: BTreeMap<String, Tensor> = BTreeMap::new();
    for node in nodes.iter().filter(|node| node.op == "MatMul") {
        let Some((layer, part)) = layer_matmul(&node.name) else { continue };
        if layer >= layers {
            return Err(refuse(format!("{} belongs to a layer beyond the {layers} of the encoder", node.name)));
        }
        let weight_name = node.inputs.get(1).ok_or_else(|| refuse(format!("{} has no weight input", node.name)))?;
        let weight =
            initializers.remove(weight_name).ok_or_else(|| refuse(format!("the weight of {} is not an initializer", node.name)))?;
        let name = format!("encoder.layer.{layer}.{part}.weight");
        if tensors.insert(name.clone(), transpose(&weight, &name)?).is_some() {
            return Err(refuse(format!("{name} is named twice")));
        }
    }
    for (name, initializer) in initializers {
        if name.starts_with("onnx::") || !(name.starts_with("embeddings.") || name.starts_with("encoder.layer.")) {
            return Err(refuse(format!("the initializer {name} is not explained")));
        }
        let tensor = Tensor { shape: initializer.shape, data: initializer.data, sha256: initializer.sha256 };
        if tensors.insert(name.clone(), tensor).is_some() {
            return Err(refuse(format!("{name} is named twice")));
        }
    }
    Ok(tensors)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn field(number: u64, wire: u64, payload: &[u8], out: &mut Vec<u8>) {
        varint((number << 3) | wire, out);
        if wire == 2 {
            varint(payload.len() as u64, out);
        }
        out.extend_from_slice(payload);
    }

    fn tensor(name: &str, dims: &[u64], values: &[f32]) -> Vec<u8> {
        let mut out = Vec::new();
        for dim in dims {
            let mut v = Vec::new();
            varint(*dim, &mut v);
            field(1, 0, &v, &mut out);
        }
        field(2, 0, &[1], &mut out);
        field(8, 2, name.as_bytes(), &mut out);
        let raw: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        field(9, 2, &raw, &mut out);
        out
    }

    fn node(name: &str, op: &str, inputs: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for input in inputs {
            field(1, 2, input.as_bytes(), &mut out);
        }
        field(3, 2, name.as_bytes(), &mut out);
        field(4, 2, op.as_bytes(), &mut out);
        out
    }

    fn model(nodes: &[Vec<u8>], tensors: &[Vec<u8>]) -> Vec<u8> {
        let mut graph = Vec::new();
        for item in nodes {
            field(1, 2, item, &mut graph);
        }
        for item in tensors {
            field(5, 2, item, &mut graph);
        }
        let mut out = Vec::new();
        field(1, 0, &[7], &mut out);
        field(7, 2, &graph, &mut out);
        out
    }

    fn one_layer() -> Vec<u8> {
        // Two inputs, three outputs: the weight is [2][3] and must come out [3][2].
        model(
            &[node("/encoder/layer.0/attention/self/query/MatMul", "MatMul", &["/x", "onnx::MatMul_9"]), node("/Shape", "Shape", &["x"])],
            &[
                tensor("onnx::MatMul_9", &[2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]),
                tensor("embeddings.word_embeddings.weight", &[1, 2], &[0.5, 0.25]),
                tensor("encoder.layer.0.attention.self.query.bias", &[3], &[0.0, 0.0, 0.0]),
            ],
        )
    }

    #[test]
    fn a_matmul_weight_is_named_by_its_node_and_transposed() {
        let tensors = encoder_tensors(&one_layer(), 1).unwrap();
        let weight = &tensors["encoder.layer.0.attention.self.query.weight"];
        assert_eq!(weight.shape, vec![3, 2]);
        assert_eq!(weight.data, vec![1.0, 4.0, 2.0, 5.0, 3.0, 6.0]);
        assert_eq!(tensors["embeddings.word_embeddings.weight"].data, vec![0.5, 0.25]);
        assert_eq!(tensors.len(), 3);
        assert_eq!(tensors["encoder.layer.0.attention.self.query.bias"].sha256, sha256_hex(&[0u8; 12]));
    }

    #[test]
    fn an_unexplained_or_misplaced_initializer_is_refused() {
        let extra = model(
            &[node("/encoder/layer.0/attention/self/query/MatMul", "MatMul", &["/x", "onnx::MatMul_9"])],
            &[tensor("onnx::MatMul_9", &[2, 3], &[0.0; 6]), tensor("onnx::Unsqueeze_5", &[1], &[0.0])],
        );
        assert!(encoder_tensors(&extra, 1).unwrap_err().to_string().contains("onnx::Unsqueeze_5"));
        assert!(encoder_tensors(&one_layer(), 0).unwrap_err().to_string().contains("beyond"));
        let missing = model(&[node("/encoder/layer.0/attention/self/query/MatMul", "MatMul", &["/x", "onnx::MatMul_9"])], &[]);
        assert!(encoder_tensors(&missing, 1).unwrap_err().to_string().contains("not an initializer"));
        let vector = model(
            &[node("/encoder/layer.0/attention/self/query/MatMul", "MatMul", &["/x", "onnx::MatMul_9"])],
            &[tensor("onnx::MatMul_9", &[6], &[0.0; 6])],
        );
        assert!(encoder_tensors(&vector, 1).unwrap_err().to_string().contains("not a matrix"));
    }

    #[test]
    fn damaged_files_are_refused_without_panicking() {
        let good = one_layer();
        for cut in [0, 1, 5, good.len() / 2, good.len() - 1] {
            assert!(encoder_tensors(&good[..cut], 1).is_err(), "cut {cut}");
        }
        let mut bad_type = tensor("embeddings.x", &[1], &[1.0]);
        bad_type[3] = 7; // data_type 7 (int64): the bytes are dims (2), then the data_type key and value
        let file = model(&[], &[bad_type]);
        assert!(encoder_tensors(&file, 1).unwrap_err().to_string().contains("not a float32"));
        let nan = model(&[], &[tensor("embeddings.x", &[1], &[f32::NAN])]);
        assert!(encoder_tensors(&nan, 1).unwrap_err().to_string().contains("not finite"));
        let twice = model(&[], &[tensor("embeddings.x", &[1], &[1.0]), tensor("embeddings.x", &[1], &[1.0])]);
        assert!(encoder_tensors(&twice, 1).unwrap_err().to_string().contains("twice"));
        assert!(encoder_tensors(&[0xff; 20], 1).is_err());
    }

    #[test]
    fn matmul_names_outside_the_layer_pattern_are_ignored() {
        assert_eq!(layer_matmul("/encoder/layer.11/output/dense/MatMul"), Some((11, "output.dense")));
        assert_eq!(layer_matmul("/encoder/layer.1/attention/self/MatMul"), None);
        assert_eq!(layer_matmul("/encoder/layer.x/output/dense/MatMul"), None);
        assert_eq!(layer_matmul("/pooler/dense/MatMul"), None);
    }
}
