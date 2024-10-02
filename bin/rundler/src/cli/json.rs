// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{fs::File, io::BufReader};

use anyhow::Context;
use aws_config::BehaviorVersion;
use serde::de::DeserializeOwned;

/// Reads and deserializes a JSON config file from a local path or an S3 bucket.
///
/// If the path starts with `s3://`, the file is read from S3 using the given region.
/// T must implement `serde::Deserialize`.
pub async fn get_json_config<T>(path: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    if path.starts_with("s3://") {
        get_s3_json_config(path).await
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

async fn get_s3_json_config<T>(path: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let config = aws_config::load_defaults(BehaviorVersion::v2024_03_28()).await;
    let client = aws_sdk_s3::Client::new(&config);

    let (bucket, key) = sscanf::sscanf!(path, "s3://{}/{}", String, String)
        .map_err(|e| anyhow::anyhow!("invalid s3 uri: {e:?}"))?;

    let object = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("should get s3 object")?;

    let body = object
        .body
        .collect()
        .await
        .context("should read s3 object body")?
        .to_vec();

    Ok(serde_json::from_slice(&body)?)
}
