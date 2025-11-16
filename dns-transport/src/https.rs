#![cfg_attr(not(feature = "with_https"), allow(unused))]

use std::io::{Read, Write};

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};

use super::tls_stream;

/// The **HTTPS transport**, which sends DNS wire data inside HTTP packets
/// encrypted with TLS, using TCP.
pub struct HttpsTransport {
    url: String,
}

impl HttpsTransport {

    /// Creates a new HTTPS transport that connects to the given URL.
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn contains_header(buf: &[u8]) -> bool {
    let header_end: [u8; 4] = [ 13, 10, 13, 10 ];
    find_subsequence(buf, &header_end).is_some()
}

use tls_stream::TlsStream;

impl Transport for HttpsTransport {

    #[cfg(any(feature = "with_https"))]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        // Use our new URL validation function that returns a Result
        let (domain, path) = self.split_domain()?;

        info!("Opening TLS socket to {:?}", domain);
        let mut stream = Self::stream(&domain, 443)?;

        debug!("Connected");

        let request_bytes = request.to_bytes().expect("failed to serialise request");
        let mut bytes_to_send = format!("\
            POST {} HTTP/1.1\r\n\
            Host: {}\r\n\
            Content-Type: application/dns-message\r\n\
            Accept: application/dns-message\r\n\
            User-Agent: {}\r\n\
            Content-Length: {}\r\n\r\n",
            path, domain, USER_AGENT, request_bytes.len()).into_bytes();
        bytes_to_send.extend(request_bytes);

        info!("Sending {} bytes of data to {:?} over HTTPS", bytes_to_send.len(), self.url);
        stream.write_all(&bytes_to_send)?;
        debug!("Wrote all bytes");

        info!("Waiting to receive...");
        // Use a Vec<u8> for a dynamically sized buffer
        let mut buf = Vec::with_capacity(4096);
        buf.resize(4096, 0);

        // Store capacity in a local variable to avoid borrowing issues
        let mut capacity = buf.capacity();
        let mut read_len = stream.read(&mut buf[0..capacity])?;

        // Keep reading until we find the header end or need to grow the buffer
        while !contains_header(&buf[0..read_len]) {
            // If we've filled the buffer and still haven't found header end, grow it
            if read_len == buf.len() {
                // Double the buffer size
                let new_capacity = buf.len() * 2;
                debug!("Growing buffer to {} bytes", new_capacity);
                buf.resize(new_capacity, 0);
                capacity = buf.capacity();
            }
            read_len += stream.read(&mut buf[read_len..capacity])?;
        }
        let mut expected_len = read_len;
        info!("Received {} bytes of data", read_len);

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut response = httparse::Response::new(&mut headers);

        // Handle HTTP parsing errors safely
        let index = match response.parse(&buf[0..read_len])? {
            httparse::Status::Complete(idx) => idx,
            httparse::Status::Partial => {
                return Err(Error::NetworkError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Incomplete HTTP response"
                )));
            }
        };

        // Get status code safely
        let code = match response.code {
            Some(c) => c,
            None => return Err(Error::HttpError(httparse::Error::HeaderName))
        };

        if code != 200 {
            let reason = response.reason.map(str::to_owned);
            return Err(Error::WrongHttpStatus(code, reason));
        }

        for header in response.headers {
            let str_value = String::from_utf8_lossy(header.value);
            debug!("Header {:?} -> {:?}", header.name, str_value);
            if header.name == "Content-Length" {
                // Parse content length safely
                match str_value.parse::<usize>() {
                    Ok(content_length) => {
                        // Check for integer overflow
                        if let Some(total_size) = index.checked_add(content_length) {
                            expected_len = total_size;
                        } else {
                            return Err(Error::NetworkError(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Content-Length too large, would cause integer overflow"
                            )));
                        }
                    },
                    Err(_) => return Err(Error::HttpError(httparse::Error::HeaderValue))
                };
            }
        }

        // Make sure we have enough space for the entire expected content
        if expected_len > buf.len() {
            debug!("Resizing buffer to fit expected content: {} bytes", expected_len);
            buf.resize(expected_len, 0);
        }

        // Continue reading until we get all expected data
        while read_len < expected_len {
            // If we've filled the buffer and need more, grow it again
            if read_len == buf.len() {
                // Double the buffer size
                let new_capacity = buf.len() * 2;
                debug!("Growing buffer to {} bytes", new_capacity);
                buf.resize(new_capacity, 0);
                capacity = buf.capacity();
            }
            read_len += stream.read(&mut buf[read_len..capacity])?;
        }

        let body = &buf[index .. read_len];
        debug!("HTTP body has {} bytes", body.len());
        let response = Response::from_bytes(&body)?;
        Ok(response)
    }

    #[cfg(not(feature = "with_https"))]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        unreachable!("HTTPS feature disabled")
    }
}

impl HttpsTransport {
    fn split_domain(&self) -> Result<(&str, &str), Error> {
        // Validate URL format
        if !self.url.starts_with("https://") {
            return Err(Error::NetworkError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid URL scheme, must be https://: {}", self.url)
            )));
        }

        // Strip the https:// prefix
        let sp = self.url.strip_prefix("https://").unwrap(); // Safe because we checked above

        // Validate there's a domain part
        if sp.is_empty() {
            return Err(Error::NetworkError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Missing domain in URL: {}", self.url)
            )));
        }

        // Find the path separator
        if let Some(slash_index) = sp.find('/') {
            // Validate domain part isn't empty
            if slash_index == 0 {
                return Err(Error::NetworkError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Missing domain in URL: {}", self.url)
                )));
            }

            // Split domain and path
            let domain = &sp[..slash_index];
            let path = &sp[slash_index..];

            // Basic domain validation - must contain at least one dot and no invalid characters
            if !domain.contains('.') || domain.contains(' ') || domain.contains('\t') || domain.contains('\n') || domain.contains('\r') {
                return Err(Error::NetworkError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid domain in URL: {}", domain)
                )));
            }

            // Path must start with a slash (which we know it does from the find above)
            Ok((domain, path))
        } else {
            // If no path separator, use root path
            Ok((sp, "/"))
        }
    }
}

/// The User-Agent header sent with HTTPS requests.
static USER_AGENT: &str = concat!("dog/", env!("CARGO_PKG_VERSION"));

