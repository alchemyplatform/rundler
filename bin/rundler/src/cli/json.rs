use std::{fs::File, io::BufReader, pin::Pin};

use anyhow::Context;
use rusoto_core::Region;
use rusoto_s3::{GetObjectRequest, S3Client, S3};
use serde::de::DeserializeOwned;
use tokio::io::AsyncReadExt;

/// Reads and deserializes a JSON config file from a local path or an S3 bucket.
///
/// If the path starts with `s3://`, the file is read from S3 using the given region.
/// T must implement `serde::Deserialize`.
pub async fn get_json_config<T>(path: &str, aws_s3_region: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    if path.starts_with("s3://") {
        get_s3_json_config(path, aws_s3_region).await
    } else {
        get_local_json_config(path)
    }
}

fn get_local_json_config<T>(path: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(serde_json::from_reader(reader)?)
}

async fn get_s3_json_config<T>(path: &str, aws_s3_region: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let aws_s3_region: Region = aws_s3_region.parse().context("invalid AWS region")?;
    let (bucket, key) = sscanf::sscanf!(path, "s3://{}/{}", String, String)
        .map_err(|e| anyhow::anyhow!("invalid s3 uri: {e:?}"))?;
    let request = GetObjectRequest {
        bucket,
        key,
        ..Default::default()
    };
    let client = S3Client::new(aws_s3_region.clone());
    let resp = client.get_object(request).await?;
    let body = resp.body.context("object should have body")?;
    let mut buf = String::new();
    Pin::new(&mut body.into_async_read())
        .read_to_string(&mut buf)
        .await?;
    Ok(serde_json::from_str(&buf)?)
}
