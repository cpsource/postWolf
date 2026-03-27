in this build, is encrypted ECH required?

● No. In the current build, ECH is available but not required. The client will use ECH if it has an ECHConfig loaded (via
  wolfSSL_CTX_SetEchConfigs), otherwise it sends a normal ClientHello (or GREASE ECH). There's no flag to make ECH
  mandatory.

  In fact, as we found in our compliance review (issue #10069, finding C12), wolfSSL doesn't even send the ech_required
  alert when ECH is rejected by the server — the handshake silently completes with the outer ClientHello. So even when a
  client tries to use ECH, there's no enforcement that it actually succeeded.

  To make ECH effectively required in your application, you'd need to check after the handshake:

  /* After wolfSSL_connect() succeeds */
  if (!ssl->options.echAccepted) {
      /* ECH was not used — abort */
      wolfSSL_shutdown(ssl);
      /* handle error */
  }

  But echAccepted is an internal field, not exposed via public API. There's no wolfSSL_get_ech_status() or equivalent
  today.

---

No. wolfSSL has no built-in rate limiting, brute force detection, connection throttling, or IP banning. It's a TLS
  library, not an application server — it handles the cryptographic handshake and encrypted transport but leaves
  connection management to the application layer.

  For that kind of protection you'd need to implement it in your application code or use external tools:

  - Application level — track failed handshakes per IP, implement backoff/ban logic around wolfSSL_accept()
  - OS level — iptables/nftables rate limiting (-m connrate, -m recent)
  - fail2ban — monitor logs for repeated TLS failures, auto-ban IPs
  - Redis + application logic — track connection attempts per IP with TTL counters

  This is typical for TLS libraries — OpenSSL, mbedTLS, and GnuTLS don't have this either. It's considered an
  application/infrastructure concern, not a crypto library concern.

---


● The natural way would be through the existing verification callback pattern that wolfSSL already uses. Here's how it
  would flow:

  Current flow (no ECH enforcement)

  wolfSSL_accept()
    → parse ClientHello
    → find ECH extension
    → try decrypt (fail/missing → silently fall back to outer)
    → complete handshake
    → return WOLFSSL_SUCCESS

  With an ECH callback

  /* Application registers a callback */
  typedef int (*EchStatusCb)(WOLFSSL* ssl, int echStatus, void* ctx);

  wolfSSL_CTX_SetEchStatusCallback(ctx, my_ech_callback, myCtx);

  The callback would fire inside wolfSSL_accept() after the ECH extension is processed but before the handshake completes:

  wolfSSL_accept()
    → parse ClientHello
    → find ECH extension (or not)
    → try decrypt
    → invoke EchStatusCb(ssl, status, ctx)
        status: ECH_ACCEPTED / ECH_REJECTED / ECH_MISSING / ECH_DECRYPT_FAIL
        callback returns: 0 = continue, <0 = abort handshake
    → if callback returns <0:
        send alert, return WOLFSSL_FATAL_ERROR
    → otherwise complete handshake
    → return WOLFSSL_SUCCESS

  What the application callback would look like

  int my_ech_callback(WOLFSSL* ssl, int echStatus, void* ctx)
  {
      const char* peer = wolfSSL_get_peer_addr(ssl); /* or similar */

      switch (echStatus) {
      case ECH_ACCEPTED:
          return 0;  /* proceed */

      case ECH_MISSING:
      case ECH_DECRYPT_FAIL:
          /* log, increment rate counter per IP, ban if threshold hit */
          log_ech_failure(peer, echStatus);
          if (is_banned(peer))
              return -1;  /* abort — wolfSSL sends alert */
          return 0;       /* allow fallback this time */

      case ECH_REJECTED:
          return 0;  /* send retry_configs as normal */

      default:
          return -1;
      }
  }

  Why this fits wolfSSL's architecture

  wolfSSL already has this pattern for:
  - wolfSSL_set_verify() — cert verification callback, fires during wolfSSL_accept(), can abort the handshake
  - wolfSSL_CTX_SetCRL_Cb() — CRL callback, same pattern
  - wolfSSL_CTX_set_cert_cb() — cert selection callback

  The ECH callback would slot into the same model — it fires at a decision point inside wolfSSL_accept(), the application
  gets context about what happened, and it returns accept/reject. The difference from the feature request (#10082) is that
   this gives the application policy control rather than just a binary on/off, so you could implement rate limiting,
  logging, gradual rollout, or IP-based rules.

  Want me to file this as a companion feature request to #10082?

❯ how are callbacks registered?

● Looking at the existing wolfSSL callback patterns:

  Searched for 2 patterns (ctrl+o to expand)

● There are two levels — CTX (shared across all connections) and SSL (per-connection):

  Pattern 1: Simple callback on CTX

  /* 1. Define the callback type */
  typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*);

  /* 2. Register on the context (applies to all connections) */
  wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myCallback);

  /* 3. Or override per-connection */
  wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, myCallback);

  Pattern 2: Callback + user data pointer

  /* 1. Define the callback type */
  typedef int (*CertSetupCallback)(WOLFSSL* ssl, void*);

  /* 2. Register with user context pointer */
  wolfSSL_CTX_set_cert_cb(ctx, myCallback, myUserData);

  Where they're stored

  The callback function pointer and optional user data are stored as fields in the WOLFSSL_CTX struct (for context-wide)
  or WOLFSSL struct (for per-connection). For example:

  /* In wolfssl/internal.h, inside WOLFSSL_CTX: */
  VerifyCallback  verifyCallback;
  CertSetupCallback certSetupCb;
  void*             certSetupCbArg;

  How the ECH callback would follow this pattern

  /* ssl.h — type definition */
  typedef int (*EchStatusCb)(WOLFSSL* ssl, int echStatus, void* userCtx);

  /* ssl.h — registration APIs */
  WOLFSSL_API void wolfSSL_CTX_SetEchStatusCb(WOLFSSL_CTX* ctx,
                                               EchStatusCb cb, void* userCtx);
  WOLFSSL_API void wolfSSL_SetEchStatusCb(WOLFSSL* ssl,
                                           EchStatusCb cb, void* userCtx);

  /* internal.h — storage in WOLFSSL_CTX */
  EchStatusCb  echStatusCb;
  void*        echStatusCbArg;

  /* tls.c — invoked inside TLSX_ECH_Parse server path */
  if (ssl->echStatusCb) {
      int cbRet = ssl->echStatusCb(ssl, status, ssl->echStatusCbArg);
      if (cbRet < 0)
          return FATAL_ERROR;  /* sends alert, aborts handshake */
  }

  This follows the exact same convention as the existing cert, CRL, and setup callbacks — typedef, CTX-level setter,
  optional per-SSL override, stored as struct fields, invoked at the decision point inside the handshake.


---

❯ where does wolfssl /var/log ?

● It doesn't. wolfSSL has no built-in logging to /var/log or any file. Its debug output goes to stderr via WOLFSSL_MSG()
  macros, and only when built with --enable-debug.

  Searched for 2 patterns (ctrl+o to expand)

● You can redirect it with a logging callback:

  void my_log(const int level, const char *msg)
  {
      /* write to syslog, file, whatever */
      syslog(LOG_INFO, "wolfssl[%d]: %s", level, msg);
  }

  wolfSSL_SetLoggingCb(my_log);
  wolfSSL_Debugging_ON();

  But by default — no file logging, no syslog, just fprintf(stderr, ...) when debug is enabled.

---

❯ any port i open to the internet is attacked by raskels, theives, and low lifes. How can I be sure tls 1.3/ECH protect
me?

● TLS 1.3 with ECH protects the transport layer — encryption, authentication, and SNI privacy. But it doesn't protect
  against everything attackers will throw at an open port. Here's what it covers and what it doesn't:

  What TLS 1.3 + ECH protects

  ┌───────────────────────────────────┬──────────────────────────────────────────┐
  │              Threat               │                Protection                │
  ├───────────────────────────────────┼──────────────────────────────────────────┤
  │ Eavesdropping on data             │ AES-256-GCM encrypts everything          │
  ├───────────────────────────────────┼──────────────────────────────────────────┤
  │ SNI snooping                      │ ECH encrypts the hostname                │
  ├───────────────────────────────────┼──────────────────────────────────────────┤
  │ Downgrade attacks                 │ TLS 1.3 has built-in downgrade detection │
  ├───────────────────────────────────┼──────────────────────────────────────────┤
  │ Replay attacks                    │ TLS 1.3 nonces prevent replay            │
  ├───────────────────────────────────┼──────────────────────────────────────────┤
  │ Server impersonation              │ Certificate verification                 │
  ├───────────────────────────────────┼──────────────────────────────────────────┤
  │ Weak cipher negotiation           │ Our build restricts to AEAD-only         │
  ├───────────────────────────────────┼──────────────────────────────────────────┤
  │ Quantum harvest-now-decrypt-later │ ML-KEM hybrid key exchange               │
  └───────────────────────────────────┴──────────────────────────────────────────┘

  What TLS 1.3 + ECH does NOT protect

  ┌───────────────────────────────────┬─────────────────────────────────────────────────┐
  │              Threat               │                    You need                     │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ Port scanning / service discovery │ Firewall rules, port knocking                   │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ Connection flooding / DDoS        │ Rate limiting (iptables -m connlimit, fail2ban) │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ Brute force auth attempts         │ Application-level lockout, rate limits          │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ Credential stuffing               │ Application-level detection                     │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ Exploits in your application code │ Input validation, patching                      │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ Zero-day in wolfSSL itself        │ Stay current on releases, monitor CVEs          │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ IP address exposure               │ VPN/Tor (ECH hides SNI, not the IP)             │
  ├───────────────────────────────────┼─────────────────────────────────────────────────┤
  │ CPU exhaustion via handshake spam │ iptables SYN rate limiting, connection limits   │
  └───────────────────────────────────┴─────────────────────────────────────────────────┘

  Practical hardening for an internet-facing port

  Layer 1: Network — before they even reach wolfSSL:
  # Limit new connections per IP
  iptables -A INPUT -p tcp --dport 2222 --syn -m connlimit --connlimit-above 5 -j DROP

  # Rate limit new connections
  iptables -A INPUT -p tcp --dport 2222 --syn -m recent --set
  iptables -A INPUT -p tcp --dport 2222 --syn -m recent --update --seconds 60 --hitcount 10 -j DROP

  Layer 2: TLS — what our build does:
  - TLS 1.3 only (no downgrade)
  - AEAD-only cipher suites
  - PQ hybrid key exchange
  - ECH for SNI privacy
  - Hardened per RFC 9325

  Layer 3: Application — your code around wolfSSL:
  - Track failed handshakes per IP
  - Implement exponential backoff
  - Log all connection attempts
  - Validate everything after decryption
  - Set timeouts on idle connections

  Layer 4: Monitoring:
  - Log failed wolfSSL_accept() calls with source IP
  - Alert on handshake failure spikes
  - Monitor for certificate scanning (many connects, no data)

  The honest answer

  TLS 1.3 + ECH makes the crypto unbreakable with current technology (and PQ hybrids hedge against future quantum). But
  attackers don't need to break the crypto — they'll go after your application logic, DoS your resources, or exploit bugs
  above the TLS layer. The TLS library is the locked door; you still need walls, a fence, and cameras.

---

 is tls 1.3 succeptable to the syn/ack attacks?

● TLS 1.3 itself doesn't operate at the TCP layer, so it neither prevents nor causes SYN/ACK attacks. The vulnerability is
   in the TCP stack underneath it.

  How it works against a TLS 1.3 server

  Attacker                          Your server
     |                                  |
     |--- SYN (spoofed IP) ----------->|  TCP allocates state (SYN queue)
     |--- SYN (spoofed IP) ----------->|  TCP allocates more state
     |--- SYN (spoofed IP) ----------->|  TCP allocates more state
     |    ... thousands more ...        |  SYN queue exhausted
     |                                  |  Legitimate clients can't connect
     |                                  |  wolfSSL_accept() never even called

  The attack exhausts TCP resources before TLS even starts. wolfSSL sits at accept() waiting for a completed TCP handshake
   that never comes.

  Even completed connections are a problem

  Attacker                          Your server
     |--- SYN --------------------->|
     |<-- SYN/ACK ------------------|
     |--- ACK --------------------->|  TCP handshake complete
     |                              |  wolfSSL_accept() starts
     |   (attacker goes silent)     |  Server waiting for ClientHello...
     |                              |  TLS resources tied up
     |   ... repeat 1000x ...       |  Thread/memory exhaustion

  TLS 1.3 is actually slightly worse than TLS 1.2 here because the server does more work in the first flight (key share
  computation, especially with ML-KEM which is CPU-intensive).

  Mitigations

  TCP level (kernel handles this):
  # Enable SYN cookies — kernel responds without allocating state
  echo 1 > /proc/sys/net/ipv4/tcp_syncookies

  # Tune SYN queue
  echo 4096 > /proc/sys/net/ipv4/tcp_max_syn_backlog

  # Reduce SYN/ACK retries
  echo 2 > /proc/sys/net/ipv4/tcp_synack_retries

  Firewall level:
  # SYN rate limit per IP
  iptables -A INPUT -p tcp --dport 2222 --syn -m hashlimit \
      --hashlimit-above 10/sec --hashlimit-burst 20 \
      --hashlimit-mode srcip --hashlimit-name syn_flood -j DROP

  Application level — in your code around wolfSSL:
  /* Set a timeout so silent connections don't hang forever */
  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  /* Then wolfSSL_accept() will fail with timeout instead of hanging */
  ret = wolfSSL_accept(ssl);

  DTLS 1.3 has a built-in answer

  If you can use UDP instead of TCP, DTLS 1.3 has a cookie exchange (stateless HelloRetryRequest) that forces the client
  to prove it can receive packets at its claimed IP before the server allocates any state. This is the TLS-layer
  equivalent of SYN cookies. wolfSSL supports DTLS 1.3 via --enable-dtls13.

  Bottom line

  SYN/ACK attacks hit TCP, not TLS. SYN cookies + firewall rate limiting are the standard defenses. wolfSSL can't help
  here — it's above the problem. The one thing you should do in your application code is set receive timeouts on sockets
  before calling wolfSSL_accept() so that slowloris-style attacks don't tie up resources indefinitely.


---

❯ what about moving encryption down into the kernel with encrypted(syn) -> etc?

● That's an interesting idea — essentially making the very first packet cryptographically authenticated so the kernel can
  reject garbage before allocating any TCP state. There are a few approaches people have explored:

  What exists today

  QUIC (UDP-based, not TCP)
  The closest production implementation of your idea. QUIC puts encryption at the transport layer — the very first packet
  contains a TLS 1.3 ClientHello inside a QUIC-encrypted frame. The server can reject unauthenticated packets statelessly.
   wolfSSL supports this via --enable-quic.

  TCP-AO (RFC 5925)
  TCP Authentication Option — adds an HMAC to every TCP segment including SYN. The kernel verifies the MAC before
  allocating state. But it requires pre-shared keys between both endpoints, so it's only practical for known peers (BGP
  routers, etc.), not public-facing servers.

  IPsec / WireGuard
  Encryption at the IP layer. SYN floods never reach the TCP stack because unauthenticated packets are dropped at the IP
  layer. But requires both sides to have keys configured — same problem as TCP-AO for public services.

  tcpcrypt (RFC 8548)
  TCP-level encryption with opportunistic key exchange in the SYN/SYN-ACK. Never got real adoption. Doesn't authenticate
  the SYN itself — it encrypts data after the handshake.

  Why encrypted SYN is hard for public servers

  The fundamental chicken-and-egg problem:

  Client                              Server
    |                                   |
    |--- Encrypted SYN --------------->|
    |                                   |
    How does the server decrypt this?
    It doesn't know who the client is yet.
    No shared key exists.

  For a public server accepting connections from unknown clients, there's no key to encrypt/authenticate the SYN with. You
   need a key exchange first, but key exchange requires a connection, which requires a SYN.

  The solutions that work around this

  ┌────────────────┬──────────────────────────────────────────────┬──────────────────────────────────────────────────┐
  │    Approach    │                     How                      │                    Trade-off                     │
  ├────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ QUIC           │ UDP + TLS 1.3 in first packet + retry token  │ No TCP at all; server validates token            │
  │                │                                              │ statelessly                                      │
  ├────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ SYN cookies    │ Kernel encodes state in the SYN-ACK sequence │ Stateless but no encryption; proven at scale     │
  │                │  number                                      │                                                  │
  ├────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ Port knocking  │ Client sends secret sequence before port     │ Security through obscurity; fragile              │
  │                │ opens                                        │                                                  │
  ├────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ WireGuard      │ All traffic inside encrypted tunnel          │ Requires key distribution; excellent for known   │
  │ tunnel         │                                              │ clients                                          │
  ├────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ ECH + QUIC     │ Encrypted SNI + encrypted transport from     │ The best current answer for public servers       │
  │                │ packet 1                                     │                                                  │
  └────────────────┴──────────────────────────────────────────────┴──────────────────────────────────────────────────┘

  The real answer for your use case

  If you want encryption from the very first packet on a public-facing service:

  QUIC + TLS 1.3 + ECH — this is exactly what you're describing. The kernel never sees a TCP SYN. Instead:

  1. Client sends a QUIC Initial packet (UDP) containing an encrypted TLS 1.3 ClientHello (with ECH)
  2. Server can validate the packet cryptographically before allocating state
  3. Server sends back a Retry token if it's suspicious — client must echo it back, proving it owns its IP
  4. Only then does the server allocate connection state

  wolfSSL supports this:
  ./configure --enable-quic --enable-ech --enable-harden-tls

  The application server (e.g., your own or something like ngtcp2/nginx-quic) handles the QUIC framing and calls wolfSSL
  for the crypto.

  Bottom line

  You can't encrypt a TCP SYN for unknown clients — there's no key yet. The industry's answer is to abandon TCP entirely
  and use QUIC, which solves this by design. If you must stay on TCP, SYN cookies + firewall rate limiting + application
  timeouts are the best you can do.

---

❯ ok, first contact is with QUIC, then convert the UDP port to TCP

● That's a solid approach — use QUIC as a gatekeeper to authenticate the client, then once trust is established, hand off
  to a TCP+TLS 1.3 connection with a session token. Essentially:

  Phase 1: QUIC knock (prove you're real)
    Client ---[QUIC+ECH]---> Server (UDP)
    Server validates, issues a short-lived token
    QUIC connection closes

  Phase 2: TCP+TLS 1.3 (real session)
    Client ---[TLS 1.3+ECH+token]---> Server (TCP)
    Server verifies token before allocating resources
    Full application session begins

  Why this works

  - SYN floods blocked — TCP port isn't open (or only accepts connections with a valid token in the first data packet)
  - Spoofed IPs eliminated — QUIC retry token proves the client owns its IP
  - ECH protects both phases — SNI encrypted in both QUIC and TCP
  - PQ-safe — ML-KEM hybrid in both phases
  - CPU exhaustion prevented — the expensive TLS handshake only happens for authenticated clients

  How to implement with wolfSSL

  wolfSSL supports both sides:

  # Build with both QUIC and TLS support
  ./configure --enable-quic --enable-harden-tls --disable-oldtls \
              --enable-mlkem --enable-ech --enable-tls-mlkem-standalone

  The QUIC gatekeeper (Phase 1) would use wolfSSL's QUIC API with a lightweight transport like ngtcp2. The token would be
  an HMAC'd timestamp + client IP:

  /* Server generates token after QUIC validation */
  /* token = HMAC-SHA256(server_secret, client_ip || timestamp) */

  /* Client presents token in TLS 1.3 session ticket or early data */
  /* Server verifies token before proceeding with handshake */

  The TCP server (Phase 2) would check the token immediately after accept(), before calling wolfSSL_accept():

  connfd = accept(listenfd, ...);

  /* Read token before TLS — raw bytes, not encrypted yet */
  n = recv(connfd, token_buf, TOKEN_SZ, MSG_PEEK);
  if (!verify_quic_token(token_buf, peer_ip)) {
      close(connfd);  /* reject — no wolfSSL resources allocated */
      continue;
  }

  /* Token valid — now do TLS */
  ssl = wolfSSL_new(ctx);
  wolfSSL_set_fd(ssl, connfd);
  wolfSSL_accept(ssl);

  Alternative: stay on QUIC entirely

  Worth considering whether you even need Phase 2. QUIC gives you:
  - Reliable, ordered delivery (like TCP)
  - Built-in encryption (TLS 1.3)
  - Connection migration (survives IP changes)
  - No head-of-line blocking

  The only reasons to switch to TCP would be:
  - Application protocol requires it (legacy compatibility)
  - Firewall environments that block UDP
  - Need long-lived connections where QUIC's overhead is wasteful

  If none of those apply, staying on QUIC for the full session is simpler and arguably more secure.

---
 how about a package where the top layer is the TCP api, but underneath is QUIC

● That's essentially what QUIC is already doing — it reimplements TCP's reliability semantics (ordered delivery, flow
  control, congestion control, retransmission) on top of UDP+TLS. The question is whether you can hide that behind a
  standard TCP socket API so applications don't need to change.

  This exists in a few forms

  MASQUE (RFC 9298)
  Proxies TCP over QUIC. Client connects via QUIC to a proxy, proxy opens TCP to the destination. The client-facing side
  gets the QUIC security properties, the backend sees normal TCP.

  QUIC-aware kernels (experimental)
  Google and Microsoft have experimented with exposing QUIC through the socket API:
  /* Hypothetical — not production yet */
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);
  connect(fd, ...);  /* looks like TCP to the app */
  write(fd, ...);    /* actually QUIC underneath */

  msquic (Microsoft)
  Has a "stream" API that looks similar to TCP sockets. Not a drop-in replacement but close.

  What you'd want: a wolfSSL shim

  Application code
      |
      | normal read()/write() on fd
      |
  [Shim layer: TCP API → QUIC translation]
      |
      | wolfSSL QUIC + ECH + ML-KEM
      |
  [UDP socket]
      |
    Network

  The shim would:
  1. Expose listen(), accept(), connect(), read(), write(), close()
  2. Internally use QUIC streams for data
  3. Handle the QUIC handshake (with ECH) transparently
  4. SYN flood protection comes free from QUIC's retry mechanism
  5. Application code unchanged — just link against the shim instead of libc sockets

  The practical approach today

  You wouldn't replace the kernel socket layer. Instead, a userspace library:

  #include "wolfquic.h"  /* drop-in replacement */

  /* Looks exactly like TCP */
  int fd = wq_socket();
  wq_listen(fd, port);
  int client = wq_accept(fd);  /* QUIC handshake happens here */
  wq_write(client, data, len); /* encrypted QUIC stream */
  wq_read(client, buf, len);
  wq_close(client);

  Underneath, wq_accept() would:
  1. Receive QUIC Initial on UDP
  2. Send Retry token (stateless — no SYN flood possible)
  3. Receive validated Initial
  4. Complete TLS 1.3 + ECH + ML-KEM via wolfSSL
  5. Return a file descriptor backed by a QUIC stream

  What already exists in the wolfSSL ecosystem

  wolfSSL provides the crypto for several QUIC implementations:
  - ngtcp2 — C library, well-tested, wolfSSL backend supported
  - curl — HTTP/3 via ngtcp2+wolfSSL

  So the building blocks are there. The missing piece is the TCP-compatible socket wrapper. ngtcp2 + wolfSSL + a thin
  socket shim would give you exactly what you're describing.

  Is it worth building?

  For your use case — internet-facing server that needs SYN flood protection with zero application changes — yes. The
  value proposition is:
  - Applications stay unchanged (standard socket API)
  - SYN floods eliminated by design (QUIC retry)
  - Encryption from first packet (no plaintext TCP handshake)
  - ECH hides what service you're connecting to
  - PQ-safe with ML-KEM

  The main cost is UDP — some corporate firewalls block it, and some network paths have poor UDP performance.

---

❯ if i did quic->tcp/wolf, how are syn attackes stopped

● They're not — that's the hole in the design. Once you convert back to TCP for the wolfSSL session, the TCP port is open
  and attackable again.

  The problem

  Attacker sees your setup:
    - UDP port 443: QUIC gatekeeper
    - TCP port 2222: wolfSSL server

  Attacker ignores the QUIC gatekeeper entirely.
  Attacker SYN floods TCP port 2222 directly.

  The QUIC phase only helps if the TCP port refuses connections without proof that the client went through QUIC first. But
   TCP has no way to verify that at the SYN level — the kernel processes the SYN before your application code can check
  anything.

  Your options

  Option 1: TCP port not publicly reachable
  Internet → [QUIC:443/UDP] → Server validates → opens localhost TCP
                                                   ↓
                                            wolfSSL on 127.0.0.1:2222
  TCP port bound to localhost only. QUIC proxy forwards validated connections internally. Attacker can't reach the TCP
  port. But now you're building a proxy.

  Option 2: Firewall allows only QUIC-authenticated IPs
  QUIC validates client → iptables -A INPUT -s <client_ip> -p tcp --dport 2222 -j ACCEPT
  Token expires → iptables -D INPUT ...
  Dynamic firewall rules. Racy, complex, doesn't survive spoofing well.

  Option 3: Stay on QUIC entirely
  Internet → [QUIC:443/UDP + wolfSSL + ECH + ML-KEM] → Application
  No TCP at all. No SYN floods possible. This is the clean answer.

  Option 4: The shim from our earlier discussion
  Internet → [UDP] → [Shim: TCP-like API over QUIC] → Application
  Application thinks it's using TCP. Shim handles everything over QUIC/UDP. No actual TCP port open. SYN floods impossible
   because there's nothing to SYN.

  Bottom line

  The moment you open a real TCP port to the internet, SYN floods are possible regardless of what happened before. The
  QUIC gatekeeper only works if the TCP port is never exposed — either loopback-only, or doesn't exist at all.

  If you want SYN flood immunity, stay on QUIC end-to-end. The TCP-compatible API shim gives you the programming model you
   want without actually opening a TCP port.

---

 is thre a github repository for QUIC

● For wolfSSL's QUIC integration, the main one is:

  ngtcp2 — the QUIC library that uses wolfSSL as its TLS backend:
  https://github.com/ngtcp2/ngtcp2

  wolfSSL's own QUIC API lives inside the wolfSSL repo itself (no separate repo):
  - --enable-quic in the configure
  - wolfssl/quic.h header
  - Used by ngtcp2 and curl for HTTP/3

  Other QUIC implementations

  ┌──────────┬─────────────────────────────────────────┬──────────┬────────────────────────────────────────────┐
  │ Project  │                   URL                   │ Language │                   Notes                    │
  ├──────────┼─────────────────────────────────────────┼──────────┼────────────────────────────────────────────┤
  │ ngtcp2   │ https://github.com/ngtcp2/ngtcp2        │ C        │ wolfSSL backend supported                  │
  ├──────────┼─────────────────────────────────────────┼──────────┼────────────────────────────────────────────┤
  │ msquic   │ https://github.com/microsoft/msquic     │ C        │ Microsoft's implementation, kernel-capable │
  ├──────────┼─────────────────────────────────────────┼──────────┼────────────────────────────────────────────┤
  │ quiche   │ https://github.com/cloudflare/quiche    │ Rust     │ Cloudflare's implementation                │
  ├──────────┼─────────────────────────────────────────┼──────────┼────────────────────────────────────────────┤
  │ lsquic   │ https://github.com/litespeedtech/lsquic │ C        │ LiteSpeed's implementation                 │
  ├──────────┼─────────────────────────────────────────┼──────────┼────────────────────────────────────────────┤
  │ picoquic │ https://github.com/nicboul/picoquic     │ C        │ Lightweight research implementation        │
  ├──────────┼─────────────────────────────────────────┼──────────┼────────────────────────────────────────────┤
  │ quinn    │ https://github.com/quinn-rs/quinn       │ Rust     │ Pure Rust                                  │
  └──────────┴─────────────────────────────────────────┴──────────┴────────────────────────────────────────────┘

  For your use case (wolfSSL + ECH + ML-KEM + QUIC), ngtcp2 is the natural choice — it already has wolfSSL integration and
   is actively maintained.

---

❯ if i started with QUIC, i could skip the tcp setup for the port by a system call that would pass appropriate info
retrieved from the QUIC, then wouldn't i convert to tcp with the synack problem?

● Right — if QUIC validates the client first, then you create a TCP socket pair internally (no network-facing TCP port),
  you get the best of both:

  Internet (UDP only)
      |
  [QUIC + wolfSSL + ECH + ML-KEM]
      |
      | Client authenticated, keys established
      |
  socketpair(AF_UNIX, SOCK_STREAM, 0)  ← no TCP port, no SYN attack surface
      |
      ├── fd[0] → application (reads/writes like TCP)
      └── fd[1] → QUIC shim (encrypts/decrypts to UDP)

  How it would work

  /* QUIC validates client over UDP */
  quic_conn = ngtcp2_accept(...);  /* wolfSSL does TLS 1.3 + ECH */

  /* Create internal socket pair — never touches the network */
  int fd[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, fd);

  /* Shim thread: QUIC stream ↔ Unix socket */
  /* reads from fd[1], encrypts, sends over UDP */
  /* receives from UDP, decrypts, writes to fd[1] */

  /* Hand fd[0] to the application */
  /* Application uses standard read()/write() */
  /* Thinks it's a normal TCP connection */

  Why SYN attacks can't happen

  - No TCP port open — nothing to SYN
  - socketpair() creates an in-kernel pipe between two file descriptors — purely local, no network stack involved
  - The only network-facing port is UDP, and QUIC's retry token mechanism handles flood protection statelessly
  - The application gets a SOCK_STREAM fd that behaves identically to TCP

  The full stack

  Application code (unmodified TCP-style)
      |  read(fd, ...) / write(fd, ...)
      |
  [fd[0]] ←socketpair→ [fd[1]]
                           |
                      [QUIC shim thread]
                           |
                      [ngtcp2 + wolfSSL]
                      TLS 1.3 + ECH + ML-KEM
                           |
                      [UDP socket :443]
                           |
                        Internet

  Zero TCP ports exposed. Application code unchanged. SYN floods impossible. This is buildable today with ngtcp2 + wolfSSL
   + a thin shim layer around socketpair().

