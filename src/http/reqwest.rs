use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use futures::io::AsyncRead;
use futures::TryStreamExt;
use json::Value;
use reqwest::Body;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use tokio_util::codec::{BytesCodec, FramedRead};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use url::Url;

use crate::error::{Error, Result};
use crate::http::HttpClient;
use crate::protocol::commands::{Request, Response};
use crate::{ClientState, ErrorCode};

/// Solves a MEGA hashcash challenge.
///
/// Challenge format: `version:easiness:timestamp:token`
/// Solution format: `version:token:counter_base64`
fn solve_hashcash(challenge: &str) -> Option<String> {
    let parts: Vec<&str> = challenge.split(':').collect();
    if parts.len() != 4 {
        tracing::error!("Invalid hashcash challenge format: expected 4 parts, got {}", parts.len());
        return None;
    }

    let version: u32 = parts[0].parse().ok()?;
    let easiness: u32 = parts[1].parse().ok()?;
    let token = parts[3];

    if version != 1 || easiness >= 256 {
        tracing::error!("Invalid hashcash parameters: version={}, easiness={}", version, easiness);
        return None;
    }

    // Calculate threshold: ((easiness & 63) << 1) + 1 << (easiness >> 6) * 7 + 3
    let threshold: u32 = (((easiness & 63) << 1) + 1) << ((easiness >> 6) * 7 + 3);

    // Decode the token from base64
    let token_bytes = BASE64_URL_SAFE_NO_PAD.decode(token).ok()?;

    // Build buffer: 4-byte prefix + 262144 copies of the 48-byte token
    const NUM_COPIES: usize = 262144;
    let mut buffer = vec![0u8; 4 + NUM_COPIES * 48];
    for i in 0..NUM_COPIES {
        buffer[4 + i * 48..4 + (i + 1) * 48].copy_from_slice(&token_bytes);
    }

    tracing::debug!("Solving hashcash challenge with easiness={}, threshold={}", easiness, threshold);

    loop {
        // Increment prefix (little-endian style, but we increment first before hashing)
        for j in 0..4 {
            buffer[j] = buffer[j].wrapping_add(1);
            if buffer[j] != 0 {
                break;
            }
        }

        // Hash the entire buffer
        let hash = Sha256::digest(&buffer);

        // Check if first 4 bytes (big-endian u32) is <= threshold
        let hash_value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);

        if hash_value <= threshold {
            let prefix = &buffer[0..4];
            let solution = BASE64_URL_SAFE_NO_PAD.encode(prefix);
            tracing::debug!("Hashcash solved with prefix: {:?}", prefix);
            return Some(format!("{}:{}:{}", version, token, solution));
        }
    }
}

#[async_trait]
impl HttpClient for reqwest::Client {
    #[tracing::instrument(skip(self, state, query_params))]
    async fn send_requests(
        &self,
        state: &ClientState,
        requests: &[Request],
        query_params: &[(&str, &str)],
    ) -> Result<Vec<Response>> {
        tracing::trace!(?self, ?state, "preparing MEGA request");

        let url = {
            let mut url = state.origin.join("/cs")?;

            let mut qs = url.query_pairs_mut();
            let id_counter = state.id_counter.fetch_add(1, Ordering::SeqCst);
            qs.append_pair("id", id_counter.to_string().as_str());

            if let Some(session) = state.session.as_ref() {
                qs.append_pair("sid", session.expose_secret().sid.as_str());
            }

            qs.extend_pairs(query_params);

            qs.finish();
            drop(qs);

            url
        };

        let mut delay = state.min_retry_delay;
        let mut hashcash_header: Option<String> = None;

        for attempt in 1..=state.max_retries {
            if attempt > 1 {
                tracing::debug!(?delay, "sleeping for exponential backoff before retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
                // TODO: maybe add some small random jitter after the doubling.
                if delay > state.max_retry_delay {
                    delay = state.max_retry_delay;
                }
            }

            // dbg!(&requests);
            tracing::debug!(?attempt, "starting MEGA request attempt");

            let request = async {
                let mut req = self.post(url.clone()).json(requests);

                if let Some(ref hashcash) = hashcash_header {
                    req = req.header("X-Hashcash", hashcash);
                }

                req.send().await
            };

            let maybe_response = if let Some(timeout) = state.timeout {
                tracing::debug!(?timeout, "attempting MEGA request with timeout");
                let Ok(maybe_response) = tokio::time::timeout(timeout, request).await else {
                    // the timeout has been reached, let's retry.
                    tracing::debug!("MEGA request has timed out");
                    continue;
                };
                maybe_response
            } else {
                request.await
            };

            let response = match maybe_response {
                Ok(response) => response,
                Err(error) => {
                    // this could be a network issue, let's retry.
                    tracing::error!(?error, "`reqwest` error when making MEGA request");
                    continue;
                }
            };

            // Handle 402 Payment Required with hashcash challenge
            if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
                if let Some(challenge) = response.headers().get("X-Hashcash") {
                    if let Ok(challenge_str) = challenge.to_str() {
                        tracing::debug!("Received hashcash challenge: {}", challenge_str);
                        // stolen straight from https://github.com/cth-latest/mega-rs/commit/718fcd524a0edf44e48fe3f16afcd82aa47477f1
                        // i didnt know his fork existed before i wrote mine, so if you are reading this you should probably use his, because i think it's better
                        if let Some(solution) = tokio::task::spawn_blocking({
                            let challenge_str = challenge_str.to_string().clone();
                            move || solve_hashcash(challenge_str.as_str())
                        }).await.expect("hashcash worker panicked") {
                            tracing::debug!("Hashcash solved, retrying with solution");
                            hashcash_header = Some(solution);
                            continue;
                        } else {
                            tracing::error!("Failed to solve hashcash challenge");
                            return Err(Error::from(reqwest::Error::from(response.error_for_status().unwrap_err())));
                        }
                    }
                }
                tracing::error!("Received 402 without valid X-Hashcash header");
                return Err(Error::from(reqwest::Error::from(response.error_for_status().unwrap_err())));
            }

            let response = match response.error_for_status() {
                Ok(response) => response,
                Err(error) => {
                    tracing::error!(?error, "HTTP error from MEGA request");
                    return Err(Error::from(error));
                }
            };

            let response = match response.bytes().await {
                Ok(response) => response,
                Err(error) => {
                    tracing::error!(?error, "Failed to read response bytes");
                    continue;
                }
            };

            // try to parse a request-level error first.
            if let Ok(code) = json::from_slice::<ErrorCode>(&response) {
                if code == ErrorCode::EAGAIN {
                    // this error code suggests we might succeed if retried, let's retry.
                    tracing::debug!("received `EAGAIN` error code from MEGA");
                    continue;
                }
                if code != ErrorCode::OK {
                    tracing::error!(?code, "received error code from MEGA");
                }
                return Err(Error::from(code));
            }

            // dbg!(&responses);
            tracing::trace!("Raw MEGA API response: {}", String::from_utf8_lossy(&response));
            let responses: Vec<Value> = match json::from_slice(&response) {
                Ok(responses) => responses,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "could not deserialize MEGA response as a JSON array",
                    );
                    tracing::error!("Raw response was: {}", String::from_utf8_lossy(&response));
                    return Err(error.into());
                }
            };

            tracing::debug!("Response array has {} elements", responses.len());
            for (i, resp) in responses.iter().enumerate() {
                tracing::debug!("Response[{}]: {}", i, resp);
            }

            return requests
                .iter()
                .zip(responses)
                .map(|(request, response)| request.parse_response_data(response))
                .collect();
        }

        tracing::error!("maximum amount of retries reached, cancelling MEGA request");

        Err(Error::MaxRetriesReached)
    }

    async fn get(&self, url: Url) -> Result<Pin<Box<dyn AsyncRead + Send>>> {
        let stream = self
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .bytes_stream()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err));

        Ok(Box::pin(stream.into_async_read()))
    }

    async fn post(
        &self,
        url: Url,
        body: Pin<Box<dyn AsyncRead + Send + Sync>>,
        content_length: Option<u64>,
    ) -> Result<Pin<Box<dyn AsyncRead + Send>>> {
        let stream = FramedRead::new(body.compat(), BytesCodec::new());
        let body = Body::wrap_stream(stream);
        let stream = {
            let mut builder = self.post(url);

            if let Some(content_length) = content_length {
                builder = builder.header("content-length", content_length);
            }

            builder
                .body(body)
                .send()
                .await?
                .error_for_status()?
                .bytes_stream()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        };

        Ok(Box::pin(stream.into_async_read()))
    }
}
