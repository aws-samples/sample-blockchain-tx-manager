//! EIP-712 typed structured data hashing
//!
//! Implements the encoding and hashing rules from <https://eips.ethereum.org/EIPS/eip-712>:
//!
//! - `encodeType`: canonical type string including referenced structs
//! - `typeHash`: keccak256(encodeType)
//! - `encodeData`: ABI-encode each field (atomic → left-padded 32 bytes,
//!   dynamic → keccak256, struct → hashStruct, array → keccak256(concat(encode each)))
//! - `hashStruct`: keccak256(typeHash ‖ encodeData)
//! - Final signing hash: keccak256("\x19\x01" ‖ hashStruct(domain) ‖ hashStruct(message))

use alloy::primitives::{B256, I256, U256, keccak256};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};

/// Standard EIP-712 typed data envelope
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedData {
    pub types: HashMap<String, Vec<FieldType>>,
    pub primary_type: String,
    pub domain: serde_json::Value,
    pub message: serde_json::Value,
}

/// A single field in a struct type definition
#[derive(Debug, Clone, Deserialize)]
pub struct FieldType {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}

/// Atomic EIP-712 types (not structs, not arrays)
const ATOMIC_TYPES: &[&str] = &[
    "address", "bool", "string", "bytes", "bytes1", "bytes2", "bytes3", "bytes4", "bytes5",
    "bytes6", "bytes7", "bytes8", "bytes9", "bytes10", "bytes11", "bytes12", "bytes13", "bytes14",
    "bytes15", "bytes16", "bytes17", "bytes18", "bytes19", "bytes20", "bytes21", "bytes22",
    "bytes23", "bytes24", "bytes25", "bytes26", "bytes27", "bytes28", "bytes29", "bytes30",
    "bytes31", "bytes32", "uint8", "uint16", "uint24", "uint32", "uint40", "uint48", "uint56",
    "uint64", "uint72", "uint80", "uint88", "uint96", "uint104", "uint112", "uint120", "uint128",
    "uint136", "uint144", "uint152", "uint160", "uint168", "uint176", "uint184", "uint192",
    "uint200", "uint208", "uint216", "uint224", "uint232", "uint240", "uint248", "uint256", "int8",
    "int16", "int24", "int32", "int40", "int48", "int56", "int64", "int72", "int80", "int88",
    "int96", "int104", "int112", "int120", "int128", "int136", "int144", "int152", "int160",
    "int168", "int176", "int184", "int192", "int200", "int208", "int216", "int224", "int232",
    "int240", "int248", "int256",
];

/// Compute the EIP-712 signing hash from full typed data.
///
/// Returns `keccak256("\x19\x01" ‖ hashStruct(domain) ‖ hashStruct(message))`.
pub fn hash_typed_data(typed_data: &TypedData) -> Result<B256, String> {
    if !typed_data.types.contains_key("EIP712Domain") {
        return Err("types must include EIP712Domain".into());
    }
    if !typed_data.types.contains_key(&typed_data.primary_type) {
        return Err(format!(
            "primaryType '{}' not found in types",
            typed_data.primary_type
        ));
    }

    let domain_hash = hash_struct("EIP712Domain", &typed_data.domain, &typed_data.types)?;
    let message_hash = hash_struct(
        &typed_data.primary_type,
        &typed_data.message,
        &typed_data.types,
    )?;

    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(domain_hash.as_slice());
    buf.extend_from_slice(message_hash.as_slice());
    Ok(keccak256(&buf))
}

/// `hashStruct(s)` = keccak256(typeHash ‖ encodeData(s))
fn hash_struct(
    type_name: &str,
    data: &serde_json::Value,
    types: &HashMap<String, Vec<FieldType>>,
) -> Result<B256, String> {
    let type_hash = type_hash(type_name, types)?;
    let encoded = encode_data(type_name, data, types)?;

    let mut buf = Vec::with_capacity(32 + encoded.len());
    buf.extend_from_slice(type_hash.as_slice());
    buf.extend_from_slice(&encoded);
    Ok(keccak256(&buf))
}

/// `typeHash(T)` = keccak256(encodeType(T))
fn type_hash(type_name: &str, types: &HashMap<String, Vec<FieldType>>) -> Result<B256, String> {
    let encoded = encode_type(type_name, types)?;
    Ok(keccak256(encoded.as_bytes()))
}

/// `encodeType(T)` — canonical type string with referenced struct types appended alphabetically.
///
/// Example: `"Mail(Person from,Person to,string contents)Person(string name,address wallet)"`
fn encode_type(type_name: &str, types: &HashMap<String, Vec<FieldType>>) -> Result<String, String> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| format!("type '{}' not found in types map", type_name))?;

    // Collect all referenced struct types (transitive)
    let mut deps = BTreeSet::new();
    collect_deps(type_name, types, &mut deps);
    deps.remove(type_name); // primary type goes first, not in the sorted deps

    let mut result = format_type_string(type_name, fields);
    for dep in &deps {
        if let Some(dep_fields) = types.get(dep.as_str()) {
            result.push_str(&format_type_string(dep, dep_fields));
        }
    }
    Ok(result)
}

fn format_type_string(name: &str, fields: &[FieldType]) -> String {
    let params: Vec<String> = fields
        .iter()
        .map(|f| format!("{} {}", f.type_, f.name))
        .collect();
    format!("{}({})", name, params.join(","))
}

/// Recursively collect struct type dependencies
fn collect_deps(
    type_name: &str,
    types: &HashMap<String, Vec<FieldType>>,
    deps: &mut BTreeSet<String>,
) {
    if !deps.insert(type_name.to_string()) {
        return; // already visited
    }
    if let Some(fields) = types.get(type_name) {
        for field in fields {
            let base = base_type(&field.type_);
            if types.contains_key(base) {
                collect_deps(base, types, deps);
            }
        }
    }
}

/// Strip array suffixes: `"Foo[]"` → `"Foo"`, `"Foo[3]"` → `"Foo"`
fn base_type(type_str: &str) -> &str {
    match type_str.find('[') {
        Some(i) => &type_str[..i],
        None => type_str,
    }
}

fn is_atomic(type_str: &str) -> bool {
    ATOMIC_TYPES.contains(&type_str)
}

fn is_array(type_str: &str) -> bool {
    type_str.ends_with(']')
}

/// `encodeData(s)` — ABI-encode each field of struct `s`.
fn encode_data(
    type_name: &str,
    data: &serde_json::Value,
    types: &HashMap<String, Vec<FieldType>>,
) -> Result<Vec<u8>, String> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| format!("type '{}' not found", type_name))?;
    let obj = data
        .as_object()
        .ok_or_else(|| format!("expected object for type '{}', got {}", type_name, data))?;

    let mut encoded = Vec::new();
    for field in fields {
        let value = obj
            .get(&field.name)
            .ok_or_else(|| format!("missing field '{}' in type '{}'", field.name, type_name))?;
        let chunk = encode_value(&field.type_, value, types)?;
        encoded.extend_from_slice(&chunk);
    }
    Ok(encoded)
}

/// Encode a single value according to its EIP-712 type. Always returns 32 bytes.
fn encode_value(
    type_str: &str,
    value: &serde_json::Value,
    types: &HashMap<String, Vec<FieldType>>,
) -> Result<Vec<u8>, String> {
    // Arrays: keccak256(concat(encode(each element)))
    if is_array(type_str) {
        let element_type = base_type(type_str);
        let items = value
            .as_array()
            .ok_or_else(|| format!("expected array for type '{}'", type_str))?;
        let mut inner = Vec::new();
        for item in items {
            inner.extend_from_slice(&encode_value(element_type, item, types)?);
        }
        return Ok(keccak256(&inner).to_vec());
    }

    // Struct reference: hashStruct
    let base = base_type(type_str);
    if types.contains_key(base) && !is_atomic(base) {
        let h = hash_struct(base, value, types)?;
        return Ok(h.to_vec());
    }

    // Atomic / dynamic types → 32 bytes
    encode_atomic(type_str, value)
}

/// Encode an atomic EIP-712 value as a left-padded 32-byte word.
fn encode_atomic(type_str: &str, value: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut word = [0u8; 32];

    match type_str {
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("expected string, got {}", value))?;
            return Ok(keccak256(s.as_bytes()).to_vec());
        }
        "bytes" => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("expected hex string for bytes, got {}", value))?;
            let bytes = decode_hex(s)?;
            return Ok(keccak256(&bytes).to_vec());
        }
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("expected address string, got {}", value))?;
            let bytes = decode_hex(s)?;
            if bytes.len() != 20 {
                return Err(format!("address must be 20 bytes, got {}", bytes.len()));
            }
            word[12..32].copy_from_slice(&bytes);
        }
        "bool" => {
            // EIP-712 `bool` is an atomic type: accept a JSON boolean only. A quoted
            // "true"/"false" is a string, not a bool, and must be rejected rather than
            // silently coerced.
            let b = value
                .as_bool()
                .ok_or_else(|| format!("expected JSON boolean for bool, got {}", value))?;
            if b {
                word[31] = 1;
            }
        }
        t if t.starts_with("uint") => {
            let bits = parse_int_width(&t[4..], t)?;
            let v = parse_uint_u256(value)?;
            // Reject values that do not fit the declared width (e.g. 256 in a uint8).
            if v.bit_len() > bits {
                return Err(format!("{} value {} exceeds {} maximum", t, v, t));
            }
            return Ok(v.to_be_bytes::<32>().to_vec());
        }
        t if t.starts_with("int") => {
            let bits = parse_int_width(&t[3..], t)?;
            let v = parse_int_i256(value)?;
            // Reject values outside [-2^(N-1), 2^(N-1)-1]. For N == 256 the I256 type is
            // itself exactly that range, so no extra bound is needed (and 1 << 255 would
            // wrap in I256).
            if bits < 256 {
                let bound = I256::ONE << (bits - 1);
                let max = bound - I256::ONE;
                let min = -bound;
                if v < min || v > max {
                    return Err(format!("{} value {} out of range", t, v));
                }
            }
            // Two's-complement big-endian, sign-extended to the full 32-byte word.
            return Ok(v.to_be_bytes::<32>().to_vec());
        }
        t if t.starts_with("bytes") => {
            // bytesN (fixed-size): right-padded
            let n: usize = t[5..]
                .parse()
                .map_err(|_| format!("invalid bytesN type: {}", t))?;
            if n == 0 || n > 32 {
                return Err(format!("invalid bytesN size: {}", n));
            }
            let s = value
                .as_str()
                .ok_or_else(|| format!("expected hex string for {}, got {}", t, value))?;
            let bytes = decode_hex(s)?;
            if bytes.len() > n {
                return Err(format!("{} value exceeds {} bytes", t, n));
            }
            // right-padded: data goes at the start
            word[..bytes.len()].copy_from_slice(&bytes);
        }
        _ => return Err(format!("unsupported type: {}", type_str)),
    }

    Ok(word.to_vec())
}

/// Parse and validate the width `N` in an EIP-712 `uintN` / `intN` type string.
///
/// Valid widths are multiples of 8 in `8..=256`; anything else is a malformed type.
fn parse_int_width(suffix: &str, type_str: &str) -> Result<usize, String> {
    let bits: usize = suffix
        .parse()
        .map_err(|_| format!("invalid integer type: {}", type_str))?;
    if !(8..=256).contains(&bits) || !bits.is_multiple_of(8) {
        return Err(format!("invalid integer width in type: {}", type_str));
    }
    Ok(bits)
}

/// Parse an unsigned integer value into a `U256`.
///
/// Accepts a JSON number (u64 range), a decimal string, or a `0x`-prefixed hex string.
/// A literal wider than 256 bits (e.g. oversized hex) is rejected as overflow rather
/// than silently truncated. Width validation against the declared `uintN` happens in the
/// caller.
fn parse_uint_u256(value: &serde_json::Value) -> Result<U256, String> {
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .map(U256::from)
            .ok_or_else(|| format!("uint value must be a non-negative integer, got {}", n)),
        serde_json::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                U256::from_str_radix(hex, 16)
                    .map_err(|_| format!("invalid or oversized uint hex string: {}", s))
            } else {
                U256::from_str_radix(s, 10)
                    .map_err(|_| format!("invalid or oversized uint decimal string: {}", s))
            }
        }
        _ => Err(format!("expected number or string for uint, got {}", value)),
    }
}

/// Parse a signed integer value into an `I256`.
///
/// Accepts a JSON number (i64 range), a signed decimal string (`-123`, `123`, `+123`),
/// or a non-negative `0x`-prefixed hex magnitude. A literal outside the int256 range is
/// rejected rather than truncated. Width validation against the declared `intN` happens
/// in the caller.
fn parse_int_i256(value: &serde_json::Value) -> Result<I256, String> {
    match value {
        serde_json::Value::Number(n) => {
            let v = n
                .as_i64()
                .ok_or_else(|| format!("int value must be a signed integer, got {}", n))?;
            I256::try_from(v).map_err(|_| format!("int value out of int256 range: {}", v))
        }
        serde_json::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let mag = U256::from_str_radix(hex, 16)
                    .map_err(|_| format!("invalid or oversized int hex string: {}", s))?;
                I256::try_from(mag)
                    .map_err(|_| format!("int hex magnitude out of int256 range: {}", s))
            } else {
                I256::from_dec_str(s).map_err(|_| format!("invalid or oversized int string: {}", s))
            }
        }
        _ => Err(format!("expected number or string for int, got {}", value)),
    }
}

/// Decode a 0x-prefixed hex string to bytes
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s).map_err(|e| format!("hex decode error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from the EIP-712 spec: Mail example
    #[test]
    fn test_eip712_mail_example() {
        let typed_data: TypedData = serde_json::from_value(serde_json::json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Person": [
                    { "name": "name", "type": "string" },
                    { "name": "wallet", "type": "address" }
                ],
                "Mail": [
                    { "name": "from", "type": "Person" },
                    { "name": "to", "type": "Person" },
                    { "name": "contents", "type": "string" }
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": { "name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
                "to": { "name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
                "contents": "Hello, Bob!"
            }
        }))
        .unwrap();

        // encodeType for Mail should include Person dependency
        let enc_type = encode_type("Mail", &typed_data.types).unwrap();
        assert_eq!(
            enc_type,
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );

        // Known EIP-712 test vector hash
        let hash = hash_typed_data(&typed_data).unwrap();
        assert_eq!(
            format!("{:?}", hash),
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn test_encode_type_single() {
        let mut types = HashMap::new();
        types.insert(
            "EIP712Domain".to_string(),
            vec![FieldType {
                name: "name".to_string(),
                type_: "string".to_string(),
            }],
        );
        let result = encode_type("EIP712Domain", &types).unwrap();
        assert_eq!(result, "EIP712Domain(string name)");
    }

    #[test]
    fn test_missing_primary_type() {
        let typed_data: TypedData = serde_json::from_value(serde_json::json!({
            "types": {
                "EIP712Domain": [{ "name": "name", "type": "string" }]
            },
            "primaryType": "Missing",
            "domain": { "name": "test" },
            "message": {}
        }))
        .unwrap();

        let result = hash_typed_data(&typed_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    // ---- Requirement 4: atomic type strictness ----

    /// `bool` accepts a JSON boolean only. A quoted string is a client error, not
    /// something to coerce (a coercing `"false"` -> true bug must be impossible).
    #[test]
    fn bool_accepts_json_boolean_only() {
        let mut t = [0u8; 32];
        t[31] = 1;
        assert_eq!(
            encode_atomic("bool", &serde_json::json!(true)).unwrap(),
            t.to_vec()
        );
        assert_eq!(
            encode_atomic("bool", &serde_json::json!(false)).unwrap(),
            [0u8; 32].to_vec()
        );
        // Strings must be rejected — including "true" and "false".
        assert!(encode_atomic("bool", &serde_json::json!("true")).is_err());
        assert!(encode_atomic("bool", &serde_json::json!("false")).is_err());
        assert!(encode_atomic("bool", &serde_json::json!(1)).is_err());
    }

    /// uint8 encodes its max (255) but rejects 256 — declared-width overflow.
    #[test]
    fn uint8_boundary_255_ok_256_rejected() {
        let enc = encode_atomic("uint8", &serde_json::json!(255)).unwrap();
        let mut want = [0u8; 32];
        want[31] = 0xFF;
        assert_eq!(enc, want.to_vec(), "uint8 255 must encode to 0x..FF");

        assert!(
            encode_atomic("uint8", &serde_json::json!(256)).is_err(),
            "uint8 256 must be rejected as overflow"
        );
        // Also via string forms.
        assert!(encode_atomic("uint8", &serde_json::json!("256")).is_err());
        assert!(encode_atomic("uint8", &serde_json::json!("0x100")).is_err());
        let enc_hex = encode_atomic("uint8", &serde_json::json!("0xff")).unwrap();
        assert_eq!(enc_hex, want.to_vec());
    }

    /// uint256 max (2^256 - 1) encodes to all-0xFF; nothing wider is representable.
    #[test]
    fn uint256_max_encodes_all_ff() {
        let max_dec =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let enc = encode_atomic("uint256", &serde_json::json!(max_dec)).unwrap();
        assert_eq!(enc, [0xFFu8; 32].to_vec(), "uint256 max must be all 0xFF");

        // Same value in hex.
        let enc_hex = encode_atomic(
            "uint256",
            &serde_json::json!(format!("0x{}", "f".repeat(64))),
        )
        .unwrap();
        assert_eq!(enc_hex, [0xFFu8; 32].to_vec());
    }

    /// A hex literal wider than 32 bytes is rejected as overflow, never truncated.
    #[test]
    fn uint256_oversized_hex_is_rejected() {
        // 33 bytes (66 hex digits) -> exceeds 2^256.
        let oversized = format!("0x{}", "1".repeat(66));
        assert!(
            encode_atomic("uint256", &serde_json::json!(oversized)).is_err(),
            "oversized hex must be rejected, not truncated"
        );
    }

    /// int8 accepts its full range [-128, 127] and rejects the values just outside it.
    #[test]
    fn int8_boundaries() {
        // 127 -> 0x..7F
        let mut want_127 = [0u8; 32];
        want_127[31] = 0x7F;
        assert_eq!(
            encode_atomic("int8", &serde_json::json!(127)).unwrap(),
            want_127.to_vec()
        );

        // -128 -> two's complement sign-extended: 0xFF.. 0x80
        let mut want_min = [0xFFu8; 32];
        want_min[31] = 0x80;
        assert_eq!(
            encode_atomic("int8", &serde_json::json!(-128)).unwrap(),
            want_min.to_vec()
        );

        // -1 -> all 0xFF (mutation-effective: distinguishes sign extension from zero fill)
        assert_eq!(
            encode_atomic("int8", &serde_json::json!(-1)).unwrap(),
            [0xFFu8; 32].to_vec()
        );

        // Just outside the range must be rejected.
        assert!(
            encode_atomic("int8", &serde_json::json!(128)).is_err(),
            "int8 128 must be rejected"
        );
        assert!(
            encode_atomic("int8", &serde_json::json!(-129)).is_err(),
            "int8 -129 must be rejected"
        );
    }

    /// int256 boundaries: min and max are two's-complement encodable; strings work too.
    #[test]
    fn int256_min_and_max_boundaries() {
        // int256 min = -2^255 -> 0x80 followed by zeros.
        let min = "-57896044618658097711785492504343953926634992332820282019728792003956564819968";
        let mut want_min = [0u8; 32];
        want_min[0] = 0x80;
        assert_eq!(
            encode_atomic("int256", &serde_json::json!(min)).unwrap(),
            want_min.to_vec()
        );

        // int256 max = 2^255 - 1 -> 0x7F followed by 0xFF.
        let max = "57896044618658097711785492504343953926634992332820282019728792003956564819967";
        let mut want_max = [0xFFu8; 32];
        want_max[0] = 0x7F;
        assert_eq!(
            encode_atomic("int256", &serde_json::json!(max)).unwrap(),
            want_max.to_vec()
        );
    }

    /// Malformed / unsupported integer widths are rejected as type errors.
    #[test]
    fn malformed_integer_widths_rejected() {
        assert!(
            parse_int_width("7", "uint7").is_err(),
            "7 not multiple of 8"
        );
        assert!(parse_int_width("264", "uint264").is_err(), "264 > 256");
        assert!(parse_int_width("0", "uint0").is_err(), "0 out of range");
        assert!(parse_int_width("x", "uintx").is_err(), "non-numeric");
        assert!(parse_int_width("8", "uint8").is_ok());
        assert!(parse_int_width("256", "uint256").is_ok());
    }

    /// A positive value supplied to a signed type still respects the reduced positive
    /// bound (2^(N-1) - 1), not the unsigned one.
    #[test]
    fn signed_positive_bound_is_half_width() {
        // 128 does NOT fit in int8 (max 127) even though it fits in uint8.
        assert!(encode_atomic("int8", &serde_json::json!(128)).is_err());
        // But 127 does.
        assert!(encode_atomic("int8", &serde_json::json!(127)).is_ok());
    }
}
