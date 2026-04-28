use crate::Result;
use serde::Serialize;
use serde_json::{Map, Value};

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let sorted = sort_value(value);
    Ok(serde_json::to_vec(&sorted)?)
}

pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String> {
    Ok(String::from_utf8(canonical_json_bytes(value)?).expect("JSON is UTF-8"))
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, sort_value(value));
            }
            Value::Object(sorted)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_recursively() {
        let value = json!({"z": 1, "a": {"b": 2, "a": 1}});
        assert_eq!(
            canonical_json_string(&value).unwrap(),
            r#"{"a":{"a":1,"b":2},"z":1}"#
        );
    }
}
