---
title: "Building an HTTP Proxy with MITM Inspection in Go: Understanding TLS,
  Certificates, and Network Security"
date: 2025-09-29
slug: "tls-http-proxy-go"
description: "A deep dive into TLS, HTTP proxies, and Go by building an HTTP proxy
  that performs MITM inspection of HTTP and HTTPS requests."
translationKey: "tls-http-proxy-go"
---

I built a minimal forward HTTP proxy that intercepts and inspects both HTTP and
HTTPS traffic in Go. This project revealed how Go's `net/http`, `crypto/tls`,
and `net.Conn` interfaces work together. Note that this post focuses exclusively
on forward proxies, not reverse proxies.

The final project is capable of:

- Forward proxying HTTP connections.
- Forward proxying HTTPS connections.
- Logging request/response pair of all HTTP(S) connections (*assuming you
  control the client's certificate authorities*).
- Blindly forwarding TCP data streams.

This post assumes basic familiarity with HTTP, TLS, and Go, but doesn't
require in-depth knowledge of these topics.

## HTTP vs HTTPS

The [Hypertext Transfer Protocol (HTTP)](https://www.cloudflare.com/learning/ddos/glossary/hypertext-transfer-protocol-http/)
implements the same request/response semantics regardless of the underlying
transport. Plain HTTP operates directly over a TCP connection, sending all data
as plaintext. HTTPS uses identical HTTP semantics but operates over an encrypted
TLS channel instead of raw TCP.

Proxying plain HTTP requests is straightforward: simply parse, forward, and
relay the response back to the client. HTTPS, however, presents a fundamental
challenge: the entire communication is encrypted in transit, preventing any
intermediary from inspecting the traffic. This encryption barrier adds
significant complexity to proxy implementation, which we'll explore later. To
understand why HTTPS creates these challenges, we first need to examine how TLS
encryption works.

## TLS

[TLS](https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/) is the
most widely used protocol to provide in-transit encryption. It allows two distinct
parties to establish a secure communication channel without sharing any secrets
beforehand, and beginning on an unencrypted channel.

TLS cleverly combines two types of encryption: asymmetric and symmetric.
Asymmetric encryption uses a pair of keys (public and private) where data encrypted
with one key can only be decrypted with the other. This solves the key exchange
problem but is computationally expensive. Symmetric encryption uses a single shared
key for both encryption and decryption—it's much faster but requires both parties
to somehow agree on the same secret key.

Another crucial aspect of TLS is that it provides both encryption and identity
verification. TLS not only creates a secure channel where outside observers cannot
read the transmitted data, but also verifies that you're communicating with the
intended destination rather than an imposter.

This verification relies on digital certificates that servers present when
establishing a connection. These certificates contain the server's public key and
identifying information. However, anyone could create a certificate claiming to be
any website, so how do we know if a certificate is legitimate?

The answer lies in Certificate Authorities (CAs) and
[digital signatures](https://en.wikipedia.org/wiki/Digital_signature). Trusted
CAs digitally sign legitimate certificates, creating a cryptographic proof that
the certificate is authentic. Your browser comes pre-installed with a list of
trusted CAs, and when connecting to a website, it verifies that the server's
certificate has been properly signed by one of these trusted authorities.

This CA verification system is crucial for understanding why our MITM proxy
requires control over the client's trusted CA list. Without it, the proxy cannot
present certificates that the client will accept as legitimate.

All of this verification and key exchange happens during what's called the TLS
handshake. This is the negotiation process that occurs before sending the actual
HTTP requests and responses.

### TLS Handshake Process

Here's a simplified overview of what happens during a TLS handshake:

1. **Client Hello**: Your browser sends a request to the server, including supported
   encryption methods
2. **Server Hello + Certificate**: The server responds with its chosen encryption
   method and presents its digital certificate (containing the public key)
3. **Certificate Verification**: Your browser verifies the certificate was signed
   by a trusted CA
4. **Key Exchange**: Using the server's public key, your browser encrypts a random
   value and sends it to the server
5. **Session Key Generation**: Both parties use this random value to generate
   identical symmetric encryption keys
6. **Secure Communication**: All subsequent data is encrypted using the fast
   symmetric encryption with the shared session key

## HTTP Proxy Fundamentals

An HTTP proxy is a server that forwards requests using the HTTP protocol as its
control channel. While commonly used for HTTP traffic, it can also tunnel arbitrary
TCP connections through HTTP CONNECT requests. The "HTTP" designation refers to
how clients communicate with the proxy, not necessarily the data being proxied.

### Plain HTTP

Proxying plain HTTP requests is straightforward. The key difference from direct
connections is that clients send the complete target URL in the request line.
Instead of `GET /path HTTP/1.1`, the client sends `GET http://example.com/path HTTP/1.1`
to the proxy, which then forwards the request to the destination server.

All other request aspects remain unchanged: headers, body, and HTTP methods are
forwarded as-is. The proxy only removes [hop-by-hop headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers#hop-by-hop_headers)
that apply to the connection between client and proxy (like `Connection` and
`Proxy-Authorization`) rather than the entire request path to the destination
server.

### HTTPS

HTTPS presents a different challenge for proxies. Since the communication is
encrypted in transit between client and server, a traditional proxy cannot
simply forward individual HTTP requests as it normally would because it cannot
see the HTTP protocol data inside the encrypted TLS stream.

The solution is the HTTP CONNECT method. When a client wants to access an HTTPS
site through a proxy, it sends a CONNECT request like `CONNECT example.com:443 HTTP/1.1`.
This tells the proxy to establish a raw TCP tunnel to the destination server.
The proxy responds with any **2xx** statuscode and then acts as a simple
TCP relay, forwarding bytes in both directions without interpretation.

At this point, the proxy effectively becomes transparent. The client now has
a direct encrypted channel to the server and can send regular HTTP requests
(like `GET /path HTTP/1.1`) instead of the full URL format used for plain HTTP
proxying. The proxy simply forwards all encrypted data without understanding
what's inside, while the client and server perform their TLS handshake and
exchange HTTP messages directly through this tunnel.

Since CONNECT establishes raw TCP tunnels, it's not limited to HTTPS. Any
TCP-based protocol can be tunneled through HTTP proxies using this method.

## Man-in-the-Middle (MITM)

Recall from the TLS section that Certificate Authorities provide cryptographic
proof of a server's identity. This CA verification system is what normally
prevents man-in-the-middle attacks. Clients trust only certificates signed by
recognized authorities, ensuring they're communicating with the intended server.

To perform MITM inspection of HTTPS traffic, a proxy must overcome this protection
by positioning itself between the client and server while maintaining TLS
encryption on both sides. This requires TLS termination: the proxy decrypts
traffic from the client using its own certificate, inspects the plaintext HTTP
data, then establishes a separate TLS connection to the upstream server to
forward the requests. Essentially, the proxy becomes the "server" from the
client's perspective and the "client" from the server's perspective, maintaining
two separate TLS connections.

For this application, the proxy must generate certificates on-the-fly for each
host it intercepts. As long as these dynamically generated certificates are
signed by the proxy's root CA and that CA is trusted by the client, the browser
will accept them as legitimate. This allows the proxy to present valid certificates
for any domain while maintaining the client's trust.

## Implementation

Finally, we have a solid ground for implementing.

### Plain HTTP Proxying

When implementing plain HTTP proxying, the initial approach might appear
straightforward:

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    resp, _ := http.DefaultClient.Do(r) // error handling will be omitted for brevity
    // write response back into w
}
```

However, this naive implementation fails with an error:
`Get "http://example.com": http: Request.RequestURI can't be set in client requests`.
This error highlights how Go treats `*http.Request` instances differently
for server and client contexts.

With this in mind, recall about the hop-by-hop headers. We have to make the adjustments
Go deems necessary, as well as remove the headers.

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    // Create a new request for the upstream server
    upstreamReq, _ := http.NewRequest(r.Method, r.RequestURI, r.Body)

    // Copy headers and remove hop-by-hop headers
    upstreamReq.Header = r.Header.Clone()
    removeHopByHopHeaders(upstreamReq.Header)

    // Clear the RequestURI field for client requests
    upstreamReq.RequestURI = ""

    resp, _ := http.DefaultClient.Do(upstreamReq)
}
```

Notice that I used `r.RequestURI` as the URL. Recall that proxied clients send the
complete target URL in the request line. `RequestURI` preserves this exactly as
received, making it perfect for proxy implementations. The documentation states:

> RequestURI is the unmodified request-target of the
> Request-Line (RFC 7230, Section 3.1.1) as sent by the client
> to a server. Usually the URL field should be used instead.
> It is an error to set this field in an HTTP client request.

Alternatively, `r.URL.String()` could be used. Note that in non-proxied requests,
`r.URL` contains only the path component without scheme or host, further illustrating
how Go handles request contexts differently.

We can implement `removeHopByHopHeaders` as:

```go
func removeHopByHopHeaders(header http.Header) {
   var hopByHopHeaders = []string{
      "Connection",
      "Proxy-Connection",
      "Keep-Alive",
      "Proxy-Authenticate",
      "Proxy-Authorization",
      "TE",
      "Trailer",
      "Transfer-Encoding",
      "Upgrade",
   }

for _, h := range hopByHopHeaders {
      header.Del(h)
   }
}
```

Now, write the response back into `http.ResponseWriter`.

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    // ... previous code ...
    resp, _ := http.DefaultClient.Do(upstreamReq)
    defer resp.Body.Close()

    // Copy response headers, removing hop-by-hop headers
    responseHeaders := resp.Header.Clone()
    removeHopByHopHeaders(responseHeaders)

    // Clear existing headers and copy filtered ones
    clear(w.Header())
    maps.Copy(w.Header(), responseHeaders)

    // Write status code and stream body
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

HTTP clients in Go handle redirects and cookies automatically through configurable
policies. However, when proxying requests, you ideally want the downstream client
to handle these behaviors rather than the proxy making decisions. For this reason,
my implementation uses `http.Transport` directly instead of `http.Client`, as
`transport.RoundTrip(req)` bypasses redirect following and cookie handling that
`client.Do(req)` would apply.

With this complete handler, we can already proxy plain HTTP requests. The proxy
correctly handles the full URL format, filters hop-by-hop headers, and streams
responses back to clients while preserving the original server behavior.

### HTTPS Proxying

Now comes the fun part. We will be proxying HTTPS requests through the CONNECT method.

#### CONNECT requests and http.Hijacker

Assume we receive a `CONNECT example.com:443 HTTP/1.1`. We can, once again, use
`r.RequestURI`.

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodConnect {
        host, port, _ := net.SplitHostPort(r.RequestURI)

        // Hijack the connection for tunneling
        hijacker, ok := w.(http.Hijacker)
        if !ok {
            http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
            return
        }
        conn, _, _ := hijacker.Hijack()

        // Send connection established response
        conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

        // Handle different connection types based on port
        if port == "443" {
            handleHTTPSConnection(conn, host)
        } else {
            handleTCPConnection(conn, host, port)
        }
        return
    }

    // Handle regular HTTP requests (previous code)
    // ...
}
```

The [`http.Hijacker`](https://pkg.go.dev/net/http@go1.25.1#Hijacker) interface
allows us to take control of the underlying TCP connection, giving us direct access
to the raw `net.Conn`. Note that HTTP/2 connections intentionally do not support
hijacking, so handlers should always test for this capability at runtime.

After sending the `200 Connection Established` response, the client expects to
establish a TLS connection through this tunnel. The proxy can now perform TLS
termination to inspect the traffic.

#### TLS Termination

We can now perform TLS termination. However, we first need a certificate for the
target host the client is attempting to reach. This requires dynamic certificate
generation, since the proxy cannot predict which hosts clients will request
during runtime.

First, we need a Certificate Authority:

```go
func generateCA() (*x509.Certificate, *rsa.PrivateKey) {
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)
    ca := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject:      pkix.Name{CommonName: "Proxy CA"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(10, 0, 0),
        IsCA:         true,
        KeyUsage:     x509.KeyUsageCertSign,
    }
    caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
    parsedCA, _ := x509.ParseCertificate(caBytes)
    return parsedCA, priv
}
```

Alternatively, you could load an existing CA from disk. This is preferable for
production use since clients need to trust the CA, and a dynamically generated
CA cannot be pre-installed in client trust stores:

```go
certPEM, _ := os.ReadFile("ca.crt")
keyPEM, _ := os.ReadFile("ca.key")
cert, _ := tls.X509KeyPair(certPEM, keyPEM)
caCert, _ := x509.ParseCertificate(cert.Certificate[0])
```

With the CA established, we can generate certificates for any hostname on demand:

```go
func generateCertificate(hostname string, caCert *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)

    // Generate random serial number - browsers may reject reused serial numbers
    serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject:      pkix.Name{CommonName: hostname},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        DNSNames:     []string{hostname},
    }
    certBytes, _ := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
    return tls.Certificate{
        Certificate: [][]byte{certBytes, caCert.Raw},
        PrivateKey:  priv,
    }
}
```

Now we can perform TLS termination by wrapping our hijacked connection. This is where
the MITM interception happens: instead of establishing a transparent tunnel, the proxy
presents its own certificate to the client, creating a TLS connection that it can
decrypt and inspect:

```go
cert := generateCertificate(host, caCert, caKey)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    NextProtos:   []string{"h2", "http/1.1"},
}

tlsConn := tls.Server(conn, tlsConfig)
tlsConn.Handshake()
```

The `NextProtos` field specifies supported application protocols for [ALPN
(Application-Layer Protocol Negotiation)](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).
This allows clients to negotiate whether to use HTTP/2 or HTTP/1.1 over the TLS
connection, which is important for modern web compatibility.

Note that `tlsConn.Handshake()` could be omitted since most applications will
trigger the handshake automatically on the first read or write operation.
However, calling it explicitly allows us to fail fast if the handshake fails,
rather than encountering the error later during request processing.

#### Parsing HTTP

We will now parse the HTTP requests, in order to proxy them similarly.

For HTTP parsing, Go provides different approaches depending on the protocol version.
For HTTP/2, we could use [`http2.Server.ServeConn()`](https://pkg.go.dev/golang.org/x/net@v0.44.0/http2#Server.ServeConn)
to handle the connection directly. For HTTP/1.x, we could use [`http.ReadRequest()`](https://pkg.go.dev/net/http@go1.25.1#ReadRequest)
to parse individual requests from the connection.

However, this approach would fragment our handling logic. We'd need separate
code paths for HTTP/1.x and HTTP/2, making our proxy more complex. More
importantly, for HTTP/1.x, using `http.ReadRequest()` alone provides no
connection management. Features like HTTP keep-alive, connection pooling, and
proper connection lifecycle handling would simply fail or require significant
additional implementation.

Instead, we can leverage Go's `http.Server` which already handles both HTTP/1.x
and HTTP/2 transparently, manages connections properly, and provides a unified
interface regardless of the underlying protocol version.

The `http.Server` typically listens for TCP connections and handles them directly.
But how can we feed our existing connections into the server? This is where [`net.Listener`](https://pkg.go.dev/net@go1.25.1#Listener)
becomes useful. Go's HTTP server accepts connections through a listener interface.
We can implement a custom listener that provides our existing connections to the server.

We can start with the following:

```go
type SingleListener struct {
    conn     net.Conn
    accepted bool
}

func (l *SingleListener) Accept() (net.Conn, error) {
    if l.accepted {
        return nil, errors.New("listener closed")
    }
    l.accepted = true
    return l.conn, nil
}

func (l *SingleListener) Close() error {
    return nil // noop
}

func (l *SingleListener) Addr() net.Addr {
    return l.conn.LocalAddr()
}
```

However, this naive approach has a critical flaw: `http.Server` will fail as soon
as the listener returns its first error from `Accept()`. This means after handling
a single connection, the server's accept loop terminates. This may cause connections
to get closed, which works against our goal of maintaining full control over
connection lifecycle and providing a stable proxy service.

```go
type SingleListener struct {
    conn      net.Conn
    accepted  atomic.Bool
    closeChan chan struct{}
    closeOnce sync.Once
}

func NewSingleListener(conn net.Conn) *SingleListener {
    return &SingleListener{
        conn:      conn,
        closeChan: make(chan struct{}),
    }
}

func (l *SingleListener) Accept() (net.Conn, error) {
    if l.accepted.CompareAndSwap(false, true) {
        return l.conn, nil
    }

    <-l.closeChan
    return nil, errors.New("listener closed")
}

func (l *SingleListener) Close() error {
    l.closeOnce.Do(func() {
        close(l.closeChan)
    })
    return nil
}

func (l *SingleListener) Addr() net.Addr {
    if l.conn != nil {
        return l.conn.LocalAddr()
    }
    return nil
}
```

Great! This implementation provides a listener that returns a single connection and then
blocks until explicitly closed. The atomic operations and channel-based blocking ensure
it's safe for concurrent use. The `sync.Once` guarantees the listener closes only once,
though the `http.Server` internals already provide similar protection.

Now we can use this listener to handle our TLS connection with an HTTP server:

```go
func handleHTTPSConnection(conn net.Conn, host string) {
    // Generate certificate for the target host
    cert := generateCertificate(host, caCert, caKey)

    // Perform TLS termination
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        NextProtos:   []string{"h2", "http/1.1"},
    }

    tlsConn := tls.Server(conn, tlsConfig)
    tlsConn.Handshake()

    // Create listener for this single connection
    listener := NewSingleListener(tlsConn)
    defer listener.Close()

    // Create HTTP server with host injection handler
    server := &http.Server{
        Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
            // Inject host context from CONNECT request
            upstreamReq := r.Clone(r.Context())
            upstreamReq.URL.Scheme = "https"
            upstreamReq.URL.Host = host
            upstreamReq.RequestURI = ""
            removeHopByHopHeaders(upstreamReq.Header)

            // Forward using the existing proxy logic
            forwardHTTPSRequest(rw, upstreamReq)
        }),
    }

    server.Serve(listener)
}
```

The key insight in this implementation is how we preserve the target hostname from
the original CONNECT request and inject it into each subsequent HTTP request. After
TLS termination, clients send path-only requests like `GET /path HTTP/1.1` without
the full hostname, but our handler reconstructs the complete URL using the host
captured during the CONNECT phase. This ensures reliable forwarding regardless of
what appears in the Host header.

The `forwardHTTPSRequest` function would implement the same forwarding logic as
the plain HTTP proxy handler shown earlier, but operating on the reconstructed
request with the complete URL.

We just have one final issue. The current code will start a server which will run forever.
Its goroutine accepting the conns will just get stuck. How can we know when to close the
server? We can use the server's ConnState callback.

> ConnState specifies an optional callback function that is
> called when a client connection changes state. See the
> ConnState type and associated constants for details.

Remember that using `http.ReadRequest()` directly would require us to manually
handle connection lifecycle and keep-alive management. The `http.Server` handles
this automatically, tracking connections through states like `StateNew`, `StateActive`,
`StateIdle` (for keep-alive), and `StateClosed`. For our single-connection proxy,
we can monitor these states to shut down when the connection terminates:

```go
func handleHTTPSConnection(conn net.Conn, host string) {
    // ... TLS termination code ...

    server := &http.Server{
        Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
            // ... request forwarding logic ...
        }),
        ConnState: func(c net.Conn, cs http.ConnState) {
            if cs == http.StateClosed || cs == http.StateHijacked {
                server.Close()
            }
        },
    }

    listener := NewSingleListener(tlsConn)
    server.Serve(listener)
}
```

We have successfully implemented HTTP and HTTPS proxying. However, our whole purpose
in implementing TLS termination and MITM interception is to inspect the decrypted traffic.
Our current implementation forwards requests but doesn't capture or analyze the data
that flows through the proxy. Let's fix that!

### Request/Response Logging

To capture and inspect the traffic flowing through our proxy, we need to log both
the incoming requests and outgoing responses. Let's extract the forwarding logic
into a separate function and add logging after the request/response pair completes:

```go
func forwardHTTPSRequest(rw http.ResponseWriter, req *http.Request) {
    // ... previous request forwarding code ...

    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(rw, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // ... copy response headers and status ...
    // ... copy response body to client ...

    // Log the complete request/response pair
    reqBody, _ := io.ReadAll(req.Body)
    respBody, _ := io.ReadAll(resp.Body)

    fmt.Printf("=== INTERCEPTED TRAFFIC ===\n")
    fmt.Printf("REQUEST: %s %s\n", req.Method, req.URL)
    fmt.Printf("Request Body: %s\n", reqBody)
    fmt.Printf("RESPONSE: %d %s\n", resp.StatusCode, resp.Status)
    fmt.Printf("Response Body: %s\n", respBody)
    fmt.Printf("===========================\n")
}
```

However, this naive approach has a fundamental problem. By the time we try to read
the request and response bodies for logging, they've already been consumed during
the forwarding process. Let's look at what proper request forwarding actually
looks like:

```go
func forwardHTTPSRequest(rw http.ResponseWriter, req *http.Request) {
    // ... previous header preparation code ...

    // Request body is consumed during RoundTrip
    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(rw, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Copy response headers
    responseHeaders := resp.Header.Clone()
    removeHopByHopHeaders(responseHeaders)
    clear(rw.Header())
    maps.Copy(rw.Header(), responseHeaders)

    // Write status and stream body to client
    rw.WriteHeader(resp.StatusCode)
    io.Copy(rw, resp.Body) // Response body is consumed here
}
```

The `io.Copy(rw, resp.Body)` operation consumes the entire response body while
streaming it to the client. Once this happens, `resp.Body` is exhausted and
cannot be read again. Similarly, if the request had a body, it would be consumed
during `RoundTrip()`.

To capture the body content for logging while still forwarding it properly, we
need a way to "tee" the data stream. We will read it once but keep it available in
memory.

Go's standard library provides `io.TeeReader` for this purpose, but there's a
catch: when we directly modify the request body (as opposed to creating a new request),
we must preserve the `io.ReadCloser` interface. The HTTP transport expects to be
able to close the body after use, as documented:

> RoundTrip must always close the body, including on errors, but depending on the
> implementation may do so in a separate goroutine even after RoundTrip returns.
> This means that callers wanting to reuse the body for subsequent requests must
> arrange to wait for the Close call before doing so.

Since we're replacing `req.Body` with our tee reader, it must implement `io.ReadCloser`
to satisfy the transport's expectations. This requirement stems from our design:
we take an existing `*http.Request` in our forwarding function and modify it directly,
assuming proper header adjustments have already been made by the HTTP server handler.
While we could handle closing explicitly and use `io.NopCloser`, our approach of
modifying the request in-place requires preserving the original interface contract.
This requires implementing our own `TeeReadCloser`:

```go
type TeeReadCloser struct {
   reader io.ReadCloser
   writer io.Writer
}

func NewTeeReadCloser(r io.ReadCloser, w io.Writer) *TeeReadCloser {
   return &TeeReadCloser{
      reader: r,
      writer: w,
   }
}

func (t *TeeReadCloser) Read(p []byte) (n int, err error) {
   n, err = t.reader.Read(p)
   if n > 0 {
      if wn, werr := t.writer.Write(p[:n]); werr != nil {
         return wn, werr
      }
   }
   return n, err
}

func (t *TeeReadCloser) Close() error {
   return t.reader.Close()
}
```

Now we can use this `TeeReadCloser` to capture both request and response bodies
while forwarding them properly. For logging, we'll use Go's [`httputil.DumpRequest`](https://pkg.go.dev/net/http/httputil@go1.25.1#DumpRequest)
and [`httputil.DumpResponse`](https://pkg.go.dev/net/http/httputil@go1.25.1#DumpResponse)
functions, which format HTTP messages in their wire representation. Exactly as they
appear on the network. This provides complete visibility into headers, status lines,
and body content in a standardized format.

Here's the complete implementation:

```go
func forwardHTTPSRequest(rw http.ResponseWriter, req *http.Request) {
    var requestBody, responseBody bytes.Buffer

    // Tee the request body if it exists
    if req.Body != nil {
        req.Body = NewTeeReadCloser(req.Body, &requestBody)
    }

    // Forward request to upstream
    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(rw, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Copy response headers
    responseHeaders := resp.Header.Clone()
    removeHopByHopHeaders(responseHeaders)
    clear(rw.Header())
    maps.Copy(rw.Header(), responseHeaders)
    rw.WriteHeader(resp.StatusCode)

    // Tee the response body
    teeReader := NewTeeReadCloser(resp.Body, &responseBody)
    io.Copy(rw, teeReader)

    // Log the complete request/response pair using httputil
    reqCopy := req.Clone(req.Context())
    reqCopy.Body = io.NopCloser(bytes.NewReader(requestBody.Bytes()))

    respCopy := *resp
    respCopy.Body = io.NopCloser(bytes.NewReader(responseBody.Bytes()))

    fmt.Printf("=== INTERCEPTED TRAFFIC ===\n")

    // DumpRequest formats the request in HTTP wire format
    reqDump, _ := httputil.DumpRequest(reqCopy, true)
    fmt.Printf("REQUEST:\n%s\n", reqDump)

    // DumpResponse formats the response in HTTP wire format
    respDump, _ := httputil.DumpResponse(&respCopy, true)
    fmt.Printf("RESPONSE:\n%s\n", respDump)

    fmt.Printf("===========================\n")
}
```

We now have complete HTTPS request logging and proxying. Our implementation intercepts
TLS-encrypted traffic, decrypts it for inspection, and forwards it to the upstream
server while capturing the full HTTP conversation. The forwarding and logging logic
for plain HTTP requests follows virtually the same pattern, just without the TLS
termination step.

### Raw TCP Tunneling

For CONNECT requests to ports other than 80 or 443, our proxy should establish
a transparent TCP tunnel without any protocol-specific handling. This covers
arbitrary TCP protocols and even HTTPS connections on non-standard ports, where
the proxy acts like a traditional non-invasive proxy:

```go
func handleTCPConnection(conn net.Conn, host, port string) {
    // Connect to the upstream server
    target := net.JoinHostPort(host, port)
    upstream, err := net.Dial("tcp", target)
    if err != nil {
        conn.Close()
        return
    }
    defer upstream.Close()

    // Create bidirectional data relay
    done := make(chan struct{}, 2)

    go func() {
        defer func() { done <- struct{}{} }()
        io.Copy(upstream, conn)
        upstream.Close()
    }()

    go func() {
        defer func() { done <- struct{}{} }()
        io.Copy(conn, upstream)
        conn.Close()
    }()

    <-done
}
```

This implementation creates two goroutines that copy data bidirectionally between
the client and upstream server. Unlike our HTTPS handler, there's no inspection
or modification. If a client uses HTTPS on a non-standard port, the traffic remains
encrypted.

## Wrapping Up

We've built a complete HTTP proxy with MITM capabilities that can intercept,
decrypt, and log both HTTP and HTTPS traffic. Our implementation covers all
three proxy modes: HTTP forwarding, HTTPS with TLS termination, and transparent
TCP tunneling.

### Example Usage

For a complete working implementation with error handling, logging, and
configuration options, see [github.com/agstrc/http-logging-proxy](https://github.com/agstrc/http-logging-proxy).

Here's how you might use the completed proxy:

```bash
# Start the proxy server
./proxy -port 8080 -logpath traffic.log

# Make requests through the proxy
curl -x localhost:8080 http://example.com
curl -k -x localhost:8080 https://example.com

# View intercepted traffic
cat traffic.log
```

The proxy logs complete request/response pairs in HTTP wire format:

```plain
=== INTERCEPTED TRAFFIC ===
REQUEST:
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.0.1
Accept: */*

RESPONSE:
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 1256

<!doctype html>
<html>...
===========================
```
