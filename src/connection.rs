use crate::{http, Request, Response};
#[cfg(feature = "https")]
use rustls::{self, ClientConfig, ClientSession};
use std::env;
use std::io::{BufReader, BufWriter, Error, ErrorKind, Read, Write};
use std::net::TcpStream;
#[cfg(feature = "https")]
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "https")]
use webpki::DNSNameRef;
#[cfg(feature = "https")]
use webpki_roots::TLS_SERVER_ROOTS;

/// A connection to the server for sending
/// [`Request`](struct.Request.html)s.
pub struct Connection {
    request: Request,
    timeout: Option<u64>,
}

impl Connection {
    /// Creates a new `Connection`. See
    /// [`Request`](struct.Request.html) for specifics about *what* is
    /// being sent.
    pub(crate) fn new(request: Request) -> Connection {
        let timeout = request
            .timeout
            .or_else(|| match env::var("MINREQ_TIMEOUT") {
                Ok(t) => t.parse::<u64>().ok(),
                Err(_) => None,
            });
        Connection { request, timeout }
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    #[cfg(feature = "https")]
    pub(crate) fn send_https(self) -> Result<Response, Error> {
        let host = self.request.host.clone();
        let is_head = self.request.method == http::Method::Head;
        let bytes = self.request.into_string().into_bytes();

        // Rustls setup
        let dns_name = host.clone();
        let dns_name = dns_name.split(":").next().unwrap();
        let dns_name = DNSNameRef::try_from_ascii_str(dns_name).unwrap();
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&TLS_SERVER_ROOTS);
        let mut sess = ClientSession::new(&Arc::new(config), dns_name);

        // IO
        let mut stream = create_tcp_stream(host, self.timeout)?;
        let mut tls = rustls::Stream::new(&mut sess, &mut stream);
        tls.write(&bytes)?;
        match read_from_stream(tls, is_head) {
            Ok(result) => Ok(Response::from_string(result)),
            Err(err) => Err(err),
        }
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    pub(crate) fn send(self) -> Result<Response, Error> {
        let host = self.request.host.clone();
        let is_head = self.request.method == http::Method::Head;
        let bytes = self.request.into_string().into_bytes();

        let tcp = create_tcp_stream(host, self.timeout)?;

        // Send request
        let mut stream = BufWriter::new(tcp);
        stream.write_all(&bytes)?;

        // Receive response
        let tcp = stream.into_inner()?;
        let mut stream = BufReader::new(tcp);
        match read_from_stream(&mut stream, is_head) {
            Ok(response) => Ok(Response::from_string(response)),
            Err(err) => match err.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => Err(Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "Request timed out! Timeout: {:?}",
                        stream.get_ref().read_timeout()
                    ),
                )),
                _ => Err(err),
            },
        }
    }
}

fn create_tcp_stream(host: String, timeout: Option<u64>) -> Result<TcpStream, Error> {
    let stream = TcpStream::connect(host)?;
    if let Some(secs) = timeout {
        let dur = Some(Duration::from_secs(secs));
        stream.set_read_timeout(dur)?;
        stream.set_write_timeout(dur)?;
    }
    Ok(stream)
}

fn parse_status_line<T: Read>(stream: &mut T) -> Result<(i32, String), Error> {
    enum State {
        HttpSlash,
        VersionMajor,
        VersionMinor,
        Code,
        Reason,
        CR,
    };
    use State::*;

    const HTTP_SLASH: &[u8] = b"HTTP/";
    let mut http_idx: usize = 0;
    let mut curr_state = HttpSlash;
    // The longest response reason (416, "Requested Range Not Satisfiable")
    // is 31 characters.
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    let mut code: i32 = 0;

    for b in stream.bytes() {
        let b = b?;
        match curr_state {
            HttpSlash => {
                if http_idx == HTTP_SLASH.len() {
                    curr_state = VersionMajor;
                } else if HTTP_SLASH[http_idx] == b {
                    http_idx += 1;
                } else {
                    break;
                }
            }

            VersionMajor => {
                if b == b'.' {
                    curr_state = VersionMinor;
                } else if !b.is_ascii_digit() {
                    break;
                }
            }

            VersionMinor => {
                if b == b' ' {
                    curr_state = Code;
                } else if !b.is_ascii_digit() {
                    break;
                }
            }

            Code => {
                // status codes are always 3 digits
                if code >= 999 {
                    break;
                }

                if b == b' ' {
                    if code < 100 {
                        break;
                    }
                    curr_state = Reason;
                } else if b.is_ascii_digit() {
                    code = 10*code + ((b - b'0') as i32);
                } else {
                    break;
                }
            }

            Reason => {
                if b == b'\r' {
                    curr_state = CR;
                } else {
                    buf.push(b);
                }
            }

            CR => {
                if b == b'\n' {
                    if let Ok(reason) = String::from_utf8(buf) {
                        return Ok((code, reason));
                    }
                }
                break;
            }
        }
    }
    return Err(Error::new(ErrorKind::Other, "not a valid HTTP status line"));
}


#[test]
fn status_line() {
    macro_rules! assert_status {
        ($status_line:expr, $method:ident) => {
            {
                let mut line: &[u8] = $status_line;
                assert!(parse_status_line(&mut line).$method());
            }
        }
    }

    assert_status!(b"HTTP/1.0 200 OK\r\n", is_ok);
    assert_status!(b"HTTP/1.0 404 Not found\r\n", is_ok);
    assert_status!(b"HTTP/1.0 404 \r\n", is_ok); // XXX: should this be accepted?

    {
        let mut line: &[u8] = b"HTTP/1.0 200 OK\r\n";
        assert_eq!((200, "OK".to_owned()), parse_status_line(&mut line).unwrap());
    }

    {
        let mut line: &[u8] = b"HTTP/1.0 404 Not found\r\n";
        assert_eq!((404, "Not found".to_owned()), parse_status_line(&mut line).unwrap());
    }

    assert_status!(b"", is_err);
    assert_status!(b"HTTP", is_err);
    assert_status!(b"HTTP/", is_err);
    assert_status!(b"HTTP/1", is_err);
    assert_status!(b"HTTP/1.", is_err);
    assert_status!(b"HTTP/1.1", is_err);
    assert_status!(b"HTTP/1.1 200", is_err);
    assert_status!(b"HTTP/1.1 200 OK", is_err);
    assert_status!(b"HTTP/1.1 200 OK\r", is_err);
    assert_status!(b"HTTP,1.1 200 OK\r\n", is_err);
    assert_status!(b"HTTP/1,1 200 OK\r\n", is_err);
    assert_status!(b"HTTP/1.1 x OK\r\n", is_err);

    assert_status!(b"HTTP/1.1 99 OK\r\n", is_err);
    assert_status!(b"HTTP/1.1 1000 OK\r\n", is_err);
}

fn parse_headers<T: Read>(stream: &mut T) -> Result<HashMap<String, String>, Error> {
    let mut bytes = stream.bytes();

}


/// Reads the stream until it can't or it reaches the end of the HTTP
/// response.
fn read_from_stream<T: Read>(stream: T, head: bool) -> Result<String, Error> {
    let mut response = String::new();
    let mut response_length = None;
    let mut chunked = false;
    let mut expecting_chunk_length = false;
    let mut byte_count = 0;
    let mut last_newline_index = 0;
    let mut blank_line = false;
    let mut status_code = None;

    for byte in stream.bytes() {
        let byte = byte?;
        let c = byte as char;
        response.push(c);
        byte_count += 1;
        if c == '\n' {
            if status_code.is_none() {
                // First line
                status_code = Some(http::parse_status_line(&response).0);
            }

            if blank_line {
                // Two consecutive blank lines, body should start here
                if let Some(code) = status_code {
                    if head || code / 100 == 1 || code == 204 || code == 304 {
                        response_length = Some(response.len());
                    }
                }
                if response_length.is_none() {
                    let len = get_response_length(&response);
                    response_length = Some(len);
                    if len > response.len() {
                        response.reserve(len - response.len());
                    }
                }
            } else if expecting_chunk_length {
                expecting_chunk_length = false;
                if let Ok(n) = usize::from_str_radix(&response[last_newline_index..].trim(), 16) {
                    // Cut out the chunk length from the reponse
                    response.truncate(last_newline_index);
                    byte_count = last_newline_index;
                    // Update response length according to the new chunk length
                    if n == 0 {
                        break;
                    } else {
                        response_length = Some(byte_count + n + 2);
                    }
                }
            } else if let Some((key, value)) = http::parse_header(&response[last_newline_index..]) {
                if key.trim() == "Transfer-Encoding" && value.trim() == "chunked" {
                    chunked = true;
                }
            }

            blank_line = true;
            last_newline_index = byte_count;
        } else if c != '\r' {
            // Normal character, reset blank_line
            blank_line = false;
        }

        if let Some(len) = response_length {
            if byte_count >= len {
                if chunked {
                    // Transfer-Encoding is chunked, next up should be
                    // the next chunk's length.
                    expecting_chunk_length = true;
                } else {
                    // We have reached the end of the HTTP response,
                    // break the reading loop.
                    break;
                }
            }
        }
    }

    Ok(response)
}

/// Tries to find out how long the whole response will eventually be,
/// in bytes.
fn get_response_length(response: &str) -> usize {
    // The length of the headers
    let mut byte_count = 0;
    for line in response.lines() {
        byte_count += line.len() + 2;
        if line.starts_with("Content-Length: ") {
            byte_count += line.clone()[16..].parse::<usize>().unwrap();
        }
    }
    byte_count
}
