use crate::models::ActionRequest;
use crate::{AuthorityError, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

pub fn action_request_from_json_str(text: &str) -> Result<ActionRequest> {
    let value = json_value_from_str_no_duplicates(text)?;
    Ok(serde_json::from_value(value)?)
}

pub fn json_value_from_str_no_duplicates(text: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = NoDuplicateJsonValue
        .deserialize(&mut deserializer)
        .map_err(AuthorityError::Json)?;
    deserializer.end().map_err(AuthorityError::Json)?;
    Ok(value)
}

struct NoDuplicateJsonValue;

impl<'de> DeserializeSeed<'de> for NoDuplicateJsonValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateJsonValueVisitor)
    }
}

struct NoDuplicateJsonValueVisitor;

impl<'de> Visitor<'de> for NoDuplicateJsonValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateJsonValue.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(NoDuplicateJsonValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            let value = map.next_value_seed(NoDuplicateJsonValue)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_key_errors_do_not_echo_key_names() {
        let err = json_value_from_str_no_duplicates(
            r#"{"sk-test-secret-value-that-must-not-echo":1,"sk-test-secret-value-that-must-not-echo":2}"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("duplicate JSON key"), "{err}");
        assert!(!err.contains("sk-test-secret-value"), "{err}");
    }
}
