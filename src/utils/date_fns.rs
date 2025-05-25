use chrono::{DateTime, Utc};
use mongodb::bson::DateTime as BsonDateTime;

pub fn format_bson_datetime(dt: Option<BsonDateTime>) -> String {
    // Convert the dt to milliseconds
    let bson_dt = dt.unwrap_or_else(BsonDateTime::now);
    let millis = bson_dt.timestamp_millis();
    // use chrono to get the date and time from millis
    let chrono_dt = DateTime::<Utc>::from_timestamp_millis(millis).unwrap_or_else(|| Utc::now());
    chrono_dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn convert_bson_datetime_to_usize(dt: BsonDateTime) -> usize {
    DateTime::<Utc>::from_timestamp_millis(dt.timestamp_millis())
        .unwrap_or_else(|| Utc::now())
        .timestamp() as usize
}
