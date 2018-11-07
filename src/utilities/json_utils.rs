use serde;
use serde_json;

pub fn to_json_str<T>(input: T) -> String
where
    T: serde::ser::Serialize,
{
    serde_json::to_string(&input).expect("Error in serialization")
}
