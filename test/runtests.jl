using Dates
using MozillaCACerts_jll
using OpenSSL
using OpenSSL_jll
using Sockets
using Test
using TimeZones

include(joinpath(dirname(pathof(OpenSSL)), "../test/http_helpers.jl"))

macro catch_exception_object(code)
    quote
        err = try
            $(esc(code))
            nothing
        catch e
            e
        end
        if err === nothing
            error("Expected exception, got $err.")
        end
        err
    end
end

# A self-signed server context for tests that talk to themselves over 127.0.0.1.
function selfsigned_server_ctx()
    cert = X509Certificate()
    key = EvpPKey(rsa_generate_key())
    cert.public_key = key
    name = X509Name()
    add_entry(name, "CN", "localhost")
    cert.subject_name = name
    cert.issuer_name = name
    Dates.adjust(cert.time_not_before, Second(0))
    Dates.adjust(cert.time_not_after, Year(1))
    sign_certificate(cert, key)
    ctx = OpenSSL.SSLContext(OpenSSL.TLSServerMethod(), "")
    OpenSSL.ssl_use_certificate(ctx, cert)
    OpenSSL.ssl_use_private_key(ctx, key)
    return ctx
end

# `accept(ssl)` runs one round of the handshake and throws `OpenSSLError` when it needs
# more bytes from the peer; this waits for them and calls again until it completes.
function accept_handshake(ssl)
    while true
        try
            return Sockets.accept(ssl)
        catch ex
            ex isa OpenSSL.OpenSSLError || rethrow()
            eof(ssl.io) && throw(EOFError())
        end
    end
end

# A connected client stream and the server stream at the other end.
function connected_pair(server_ctx, server)
    server_task = @async begin
        ssl = OpenSSL.SSLStream(server_ctx, accept(server))
        accept_handshake(ssl)
        ssl
    end
    port = Sockets.getsockname(server)[2]
    client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
        Sockets.connect(ip"127.0.0.1", port))
    Sockets.connect(client; require_ssl_verification=false)
    return client, fetch(server_task)
end

# A finished task's value, or the exception it failed with (not the TaskFailedException
# `fetch` wraps it in), for the caller to assert on.
taskoutcome(task) = istaskfailed(task) ? task.result : fetch(task)

# `task`'s outcome should it finish within `timeout`, else `placeholder`; nothing waits
# on a task that stalled.
boundedfetch(task, placeholder; timeout=30.0) =
    timedwait(() -> istaskdone(task), timeout) === :ok ? taskoutcome(task) : placeholder

# Bytes handed to libuv that have not left for the kernel yet.
function writequeuesize(io::TCPSocket)
    Base.iolock_begin()
    try
        io.handle == C_NULL && return 0
        return Int(ccall(:uv_stream_get_write_queue_size, Csize_t, (Ptr{Cvoid},), io.handle))
    finally
        Base.iolock_end()
    end
end

# Writes to `io` (the stream, or its socket for a raw write) until the peer's receive
# window is full and the writer parks on the socket; returns the task and the count of
# completed writes. Each write is many times what goes
# to OpenSSL in one call, and more than the kernel's send and receive buffers grow to
# (Windows and macOS keep growing them for a peer that does not read): a parked write
# that the buffers could still take would complete of itself.
const PARK_CHUNK = max(32 * 2^20, 3 * Int(OpenSSL.SSL_WRITE_CHUNK))
function park_writer(client, stop_writing; io=client)
    written = Threads.Atomic{Int}(0)
    chunk = zeros(UInt8, PARK_CHUNK)
    writer = @async try
        while !stop_writing[]
            write(io, chunk)
            Threads.atomic_add!(written, length(chunk))
        end
        nothing
    catch ex
        ex
    end
    # parked means: bytes in libuv that have not left for the kernel, the same amount
    # half a second later, and no write completed meanwhile
    parked = timedwait(60.0; pollint=0.5) do
        before = (written[], writequeuesize(client.io))
        sleep(0.5)
        !istaskdone(writer) && before[2] > 0 && (written[], writequeuesize(client.io)) == before
    end
    if parked !== :ok
        outcome = istaskdone(writer) ? fetch(writer) : "still writing"
        close(client, false)
        error("the writer did not park on the socket: $outcome")
    end
    return writer, written
end

# Whether every run of one writer's byte in `received` is whole writes of that writer long.
function wholewrites(received, chunklen)
    i = 1
    while i <= length(received)
        j = i
        while j <= length(received) && received[j] == received[i]
            j += 1
        end
        (j - i) % chunklen(Int(received[i])) == 0 || return false
        i = j
    end
    return true
end

# A client stream connecting to `port` on a task, for a server that drives its side of
# the handshake itself.
function connecting(port)
    @async begin
        client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
            Sockets.connect(ip"127.0.0.1", port))
        Sockets.connect(client; require_ssl_verification=false)
        client
    end
end

# Verifies calling into OpenSSL library.
@testset "OpenSSL" begin
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_create_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_destroy_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_read_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_write_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_puts_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_ctrl_ptr != C_NULL
end

@testset "RandomBytes" begin
    random_data = random_bytes(64)

    @test length(random_data) == 64
end

@testset "BigNumbers" begin
    n1 = BigNum(0x4)
    n2 = BigNum(0x8)
    @test String(n1 + n2) == "0xC"

    #n4 = n3 - n1 - n2 - n3
    #n5 = BigNum(0x2)
    #@show n1, n2, n3, n4, n1 * n5

    n1 = BigNum(0x10)
    n2 = BigNum(0x4)
    @test String(n1 / n2) == "0x4"

    n1 = BigNum(0x11)
    @test String(n1 % n2) == "0x1"

    n1 = BigNum(0x3)
    @test String(n1 * n2) == "0xC"
end

@testset "Asn1Time" begin
    @test String(Asn1Time()) == "Jan  1 00:00:00 1970 GMT"
    @test String(Asn1Time(2)) == "Jan  1 00:00:02 1970 GMT"

    asn1_time = Asn1Time()
    Dates.adjust(asn1_time, Dates.Second(4))

    OpenSSL.free(asn1_time)
    @test String(asn1_time) == "C_NULL"

    # double free
    OpenSSL.free(asn1_time)
    @test String(asn1_time) == "C_NULL"

    Dates.adjust(asn1_time, Dates.Second(4))
    Dates.adjust(asn1_time, Dates.Second(4))
    Dates.adjust(asn1_time, Dates.Day(4))
    Dates.adjust(asn1_time, Dates.Year(2))

    @show asn1_time
end

@testset "X509Name" begin
    x509_name_1 = X509Name()
    add_entry(x509_name_1, "C", "US")
    add_entry(x509_name_1, "ST", "Isles of Redmond")
    add_entry(x509_name_1, "CN", "www.redmond.com")

    x509_name_2 = X509Name()
    add_entry(x509_name_2, "C", "US")
    @test x509_name_1 != x509_name_2

    add_entry(x509_name_2, "ST", "Isles of Redmond")
    @test x509_name_1 != x509_name_2

    add_entry(x509_name_2, "CN", "www.redmond.com")
    @test x509_name_1 == x509_name_2
end

@testset "ReadPEMCert" begin
    file_handle = open(MozillaCACerts_jll.cacert)
    file_content = String(read(file_handle))
    close(file_handle)

    start_line = "==========\n"
    certs_pem = split(file_content, start_line; keepempty=false)

    # Mozilla's root list changes order over time, so use the first root whose subject has an OU
    pems = filter(p -> occursin("-----BEGIN CERTIFICATE-----", p), certs_pem)
    x509_cert = first(c for c in Iterators.map(X509Certificate, pems) if occursin("/OU=", String(c.subject_name)))

    @test occursin("/C=", String(x509_cert.subject_name))
    @test occursin("/OU=", String(x509_cert.subject_name))
    @test  occursin("/CN=", String(x509_cert.subject_name))

    @test occursin("/C=", String(x509_cert.issuer_name))
    @test occursin("/OU=", String(x509_cert.issuer_name))
    @test  occursin("/CN=", String(x509_cert.issuer_name))

    s_before_time = replace(String(x509_cert.time_not_before), r" +" => " ")
    @test DateTime(s_before_time, dateformat"u d HH:MM:SS yyyy Z") < today()

    s_after_time = replace(String(x509_cert.time_not_after), r" +" => " ")
    @test DateTime(s_after_time, dateformat"u d HH:MM:SS yyyy Z") > today()

    # finalizer will cleanup
    #finalize(x509_cert)
end

# The time of a certificate that is garbage once this returns.
@noinline time_of_dropped_cert(pem) = X509Certificate(pem).time_not_after

@testset "CertificateTimeKeepsCertificate" begin
    # A certificate's time points into the certificate: it keeps the certificate alive
    # while it is in use, and freeing it leaves the certificate's own time alone.
    pem = read(joinpath(@__DIR__, "certs", "1001acf7.0"), String)
    expected = String(X509Certificate(pem).time_not_after)
    for _ in 1:20
        t = time_of_dropped_cert(pem)
        GC.gc(true)
        @test String(t) == expected
    end

    cert = X509Certificate(pem)
    t = cert.time_not_after
    free(cert)
    GC.gc(true)
    @test String(t) == expected

    cert = X509Certificate(pem)
    t = cert.time_not_after
    free(t)
    @test String(t) == "C_NULL"
    @test String(cert.time_not_after) == expected
    # the view's time is the certificate's own: adjusting it changes the certificate
    Dates.adjust(cert.time_not_after, Year(1))
    @test String(cert.time_not_after) != expected
end

@testset "StackOf{X509Certificate}" begin
    file_handle = open(MozillaCACerts_jll.cacert)
    file_content = String(read(file_handle))
    close(file_handle)

    start_line = "==========\n"
    certs_pem = split(file_content, start_line; keepempty=false)

    x509_certificates = StackOf{X509Certificate}()

    foreach(2:length(certs_pem)) do i
        x509_cert = X509Certificate(certs_pem[i])
        push!(x509_certificates, x509_cert)
        finalize(x509_cert)
        nothing
    end

    free(x509_certificates)
end

@testset "StackOf{BigNum}" begin
    n1 = BigNum(0x4)
    n2 = BigNum(0x8)

    big_nums = StackOf{BigNum}()
    push!(big_nums, n1)
    push!(big_nums, n2)

    _n1 = pop!(big_nums)
    _n2 = pop!(big_nums)

    @test _n1 == n2
    @test _n1 == n2
end

@testset "X509Store" begin
    file_handle = open(MozillaCACerts_jll.cacert)
    file_content = String(read(file_handle))
    close(file_handle)

    start_line = "==========\n"

    certs_pem = split(file_content, start_line; keepempty=false)

    # X509 store.
    x509_store = X509Store()

    foreach(2:length(certs_pem)) do i
        x509_cert = X509Certificate(certs_pem[i])
        add_cert(x509_store, x509_cert)
        free(x509_cert)
        nothing
    end

    free(x509_store)
end

@testset "HttpsConnect" begin
    tcp_stream = connect("httpbingo.julialang.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    ssl = SSLStream(ssl_ctx, tcp_stream)

    OpenSSL.connect(ssl)

    x509_server_cert = OpenSSL.get_peer_certificate(ssl)

    @test occursin("/C=US/O=Let's Encrypt", String(x509_server_cert.issuer_name))
    @test String(x509_server_cert.subject_name) == "/CN=httpbingo.julialang.org"

    request_str = "GET /status/200 HTTP/1.1\r\nHost: httpbingo.julialang.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

    written = write(ssl, request_str)

    @test !eof(ssl)
    io = IOBuffer()
    sleep(2)
    write(io, readavailable(ssl))
    response = String(take!(io))
    @test startswith(response, "HTTP/1.1 200 OK\r\n")
    sleep(2)
    @test isempty(readavailable(ssl))
    # start a bunch of tasks all racing to call eof
    tasks = [@async(eof(ssl)) for _ = 1:100]
    yield()
    @test all(t -> !istaskdone(t), tasks)
    closetasks = [@async(close(ssl)) for _ = 1:100]
    yield()
    sleep(2)
    finalize(ssl_ctx)
    @test all(t -> istaskdone(t), tasks)
    @test all(t -> istaskdone(t), closetasks)
end

@testset "ClosedStream" begin
    tcp_stream = connect("www.nghttp2.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)
    OpenSSL.ssl_set_ciphersuites(ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")

    ssl = SSLStream(ssl_ctx, tcp_stream)

    OpenSSL.connect(ssl)

    # Close the ssl stream.
    close(ssl)

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

    @test_throws Base.IOError unsafe_write(ssl, pointer(request_str), length(request_str))
    finalize(ssl_ctx)
end

@testset "NoCloseStream" begin
    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    tcp_stream = connect("www.nghttp2.org", 443)
    ssl = SSLStream(ssl_ctx, tcp_stream)
    OpenSSL.connect(ssl)

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"
    unsafe_write(ssl, pointer(request_str), length(request_str))

    @test !eof(ssl)
    io = IOBuffer()
    sleep(2)
    write(io, readavailable(ssl))
    response = String(take!(io))
    @test startswith(response, "HTTP/1.1 200 OK\r\n")

    # Do not close SSLStream, leave it to the finalizer.
    #close(ssl)
    #finalize(ssl_ctx)
end

@testset "Hash" begin
    @test_throws ErrorException EvpMD2()
    @test_throws ErrorException EvpDSS1()
    res = digest(EvpMD5(), IOBuffer("The quick brown fox jumps over the lazy dog"))
    @test res == UInt8[0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6]
    @test bytes2hex(digest(OpenSSL.EvpRIPEMD160(), IOBuffer("abc"))) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
end

@testset "HMAC" begin
    # echo -n "Hello world" | openssl dgst -sha256 -mac hmac -macopt hexkey:01020304
    @test bytes2hex(OpenSSL.hmac(OpenSSL.EvpSHA256(), "Hello world", hex2bytes("01020304"))) == "760e94f3d42452f372885f22d3ed5915ffa5a7d6ddf38716331f9c2786f21e5a"

    # echo -n "Hello world" | openssl dgst -sha512 -hmac "Σλ"
    @test bytes2hex(OpenSSL.hmac(OpenSSL.EvpSHA512(), "Hello world", "Σλ")) == "dfe48de81d0f5f8976d20e10c6fa2f82ff3cc28ae5060b396f70e26d45563a4cfa446d53d5fbea377018b54dac1ec368c979fb2b4a99f642cb0a2d8422c3bfa6"
    @test OpenSSL.hmac(OpenSSL.EvpSHA512(), Vector{UInt8}("Hello world"), "Σλ") == OpenSSL.hmac(OpenSSL.EvpSHA512(), "Hello world", "Σλ")

    # echo -n "Hello world" | openssl dgst -sha256 -hmac ""
    @test bytes2hex(OpenSSL.hmac(OpenSSL.EvpSHA256(), [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64], b"")) == "c50d316a00f927059322a898ea2fa7321fdb4d32eb749656ea7ba7775a870dc0"

    # inputs not stored as one block of memory give the MAC of their bytes
    data = rand(UInt8, 100)
    key = rand(UInt8, 20)
    @test OpenSSL.hmac(OpenSSL.EvpSHA256(), view(data, 1:2:100), key) == OpenSSL.hmac(OpenSSL.EvpSHA256(), data[1:2:100], key)
    @test OpenSSL.hmac(OpenSSL.EvpSHA256(), data, 0x01:0x14) == OpenSSL.hmac(OpenSSL.EvpSHA256(), data, collect(0x01:0x14))
end

@testset "SelfSignedCertificate" begin
    x509_certificate = X509Certificate()

    evp_pkey = EvpPKey(rsa_generate_key())
    x509_certificate.public_key = evp_pkey

    x509_name = X509Name()
    add_entry(x509_name, "C", "US")
    add_entry(x509_name, "ST", "Isles of Redmond")
    add_entry(x509_name, "CN", "www.redmond.com")

    x509_certificate.subject_name = x509_name
    x509_certificate.issuer_name = x509_name

    Dates.adjust(x509_certificate.time_not_before, Second(0))
    Dates.adjust(x509_certificate.time_not_after, Year(1))

    add_extension(x509_certificate, X509Extension("basicConstraints", "CA:TRUE"))
    add_extension(x509_certificate, X509Extension("keyUsage", "keyCertSign"))

    sign_certificate(x509_certificate, evp_pkey)

    io = IOBuffer()
    n = write(io, x509_certificate)
    cert_pem = String(take!(io))
    @test n == sizeof(cert_pem)
    @test startswith(cert_pem, "-----BEGIN CERTIFICATE-----")

    x509_certificate2 = X509Certificate(cert_pem)

    x509_string = String(x509_certificate)
    x509_string2 = String(x509_certificate2)

    public_key = x509_certificate.public_key

    @test x509_string == x509_string2

    # text ahead of the PEM block may be non-ASCII
    @test X509Certificate("friendlyName: Zoë Ünïcödé\n" * cert_pem) == x509_certificate

    p12_object = P12Object(evp_pkey, x509_certificate)

    io = IOBuffer()
    n = write(io, p12_object)
    @test n > 0
    @test n == length(take!(io))

    OpenSSL.unpack(p12_object)
end

@testset "SignCertCertificate" begin
    # Create a root certificate.
    x509_certificate = X509Certificate()

    evp_pkey_ca = EvpPKey(rsa_generate_key())
    x509_certificate.public_key = evp_pkey_ca

    x509_name = X509Name()
    add_entry(x509_name, "C", "US")
    add_entry(x509_name, "ST", "Isles of Redmond")
    add_entry(x509_name, "CN", "www.redmond.com")

    x509_certificate.subject_name = x509_name
    x509_certificate.issuer_name = x509_name

    Dates.adjust(x509_certificate.time_not_before, Second(0))
    Dates.adjust(x509_certificate.time_not_after, Year(1))

    add_extension(x509_certificate, X509Extension("basicConstraints", "CA:TRUE"))
    add_extension(x509_certificate, X509Extension("keyUsage", "keyCertSign"))

    sign_certificate(x509_certificate, evp_pkey_ca)

    root_certificate = x509_certificate

    # Create a certificate sign request.
    x509_request = X509Request()
    @test x509_request.version == 0

    evp_pkey = EvpPKey(rsa_generate_key())

    x509_name = X509Name()
    add_entry(x509_name, "C", "US")
    add_entry(x509_name, "ST", "Isles of Redmond")
    add_entry(x509_name, "CN", "www.redmond.com")

    x509_request.subject_name = x509_name

    x509_exts = StackOf{X509Extension}()

    ext = X509Extension("subjectAltName", "DNS:localhost")
    push!(x509_exts, ext)
    add_extensions(x509_request, x509_exts)
    finalize(ext)

    finalize(x509_exts)

    sign_request(x509_request, evp_pkey)

    io = IOBuffer()
    n = write(io, x509_request)
    req_pem = String(take!(io))
    @test n == sizeof(req_pem)
    @test startswith(req_pem, "-----BEGIN CERTIFICATE REQUEST-----")

    # Create a certificate.
    x509_certificate = X509Certificate()
    x509_certificate.version = 2

    # Set issuer and subject name of the cert from the req and CA.
    x509_certificate.subject_name = x509_request.subject_name
    x509_certificate.issuer_name = root_certificate.subject_name

    x509_exts = x509_request.extensions

    ext = pop!(x509_exts)

    add_extension(x509_certificate, ext)
    add_extension(x509_certificate, X509Extension("keyUsage", "digitalSignature, nonRepudiation, keyEncipherment"))
    add_extension(x509_certificate, X509Extension("basicConstraints", "CA:FALSE"))

    # Set public key
    x509_certificate.public_key = x509_request.public_key

    Dates.adjust(x509_certificate.time_not_before, Second(0))
    Dates.adjust(x509_certificate.time_not_after, Year(1))

    sign_certificate(x509_certificate, evp_pkey_ca)
end

@testset "ErrorTaskTLS" begin
    err_msg = OpenSSL.get_error()
    @test err_msg == ""

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSServerMethod())

    # Make direct invalid call to OpenSSL
    invalid_cipher_suites = "TLS_AES_356_GCM_SHA384"
    result = ccall(
        (:SSL_CTX_set_ciphersuites, libssl),
        Cint,
        (OpenSSL.SSLContext, Cstring),
        ssl_ctx,
        invalid_cipher_suites)

    # Verify the error message.
    err_msg = OpenSSL.get_error()
    @test contains(err_msg, "no cipher match")

    # Ensure error queue is empty.
    err_msg = OpenSSL.get_error()
    @test err_msg == ""

    # Make invalid OpenSSL (with fail and OpenSSL updates internal error queue).
    result = ccall(
        (:SSL_CTX_set_ciphersuites, libssl),
        Cint,
        (OpenSSL.SSLContext, Cstring),
        ssl_ctx,
        invalid_cipher_suites)
    # Copy and clear OpenSSL error queue to task TLS.
    OpenSSL.update_tls_error_state()
    # OpenSSL queue should be empty right now.
    @test ccall((:ERR_peek_error, libcrypto), Culong, ()) == 0

    # Verify the error message, error message should be retrived from the task TLS.
    err_msg = OpenSSL.get_error()
    @test contains(err_msg, "no cipher match")

    free(ssl_ctx)
end

@testset "PKCS12" begin
    x509_certificate = X509Certificate()

    evp_pkey = EvpPKey(rsa_generate_key())
    x509_certificate.public_key = evp_pkey

    x509_name = X509Name()
    add_entry(x509_name, "C", "US")
    add_entry(x509_name, "ST", "Isles of Redmond")
    add_entry(x509_name, "CN", "www.redmond.com")

    x509_certificate.subject_name = x509_name
    x509_certificate.issuer_name = x509_name

    Dates.adjust(x509_certificate.time_not_before, Second(0))
    Dates.adjust(x509_certificate.time_not_after, Year(1))

    sign_certificate(x509_certificate, evp_pkey)

    p12_object = P12Object(evp_pkey, x509_certificate)

    _evp_pkey, _x509_certificate, _x509_ca_stack = unpack(p12_object)

    @test _evp_pkey == evp_pkey
    @test _evp_pkey.key_type == evp_pkey.key_type

    @test _x509_certificate == x509_certificate
    @test _x509_certificate.subject_name == x509_certificate.subject_name
    @test _x509_certificate.issuer_name == x509_certificate.issuer_name
end

# https://www.openssl.org/docs/man3.0/man7/OSSL_PROVIDER-legacy.html
@testset "Encrypt" begin
    evp_ciphers = [
        EvpEncNull(),
        #EvpBlowFishCFB(), // not supported
        EvpAES128CBC(),
        EvpAES128ECB(),
        #EvpAES128CFB(), // not supported
        EvpAES128OFB(),
    ]

    foreach(evp_ciphers) do evp_cipher
        sym_key = random_bytes(evp_cipher.key_length)
        init_vector = random_bytes(evp_cipher.init_vector_length)

        enc_evp_cipher_ctx = EvpCipherContext()
        encrypt_init(enc_evp_cipher_ctx, evp_cipher, sym_key, init_vector)

        dec_evp_cipher_ctx = EvpCipherContext()
        decrypt_init(dec_evp_cipher_ctx, evp_cipher, sym_key, init_vector)

        in_string = "OpenSSL Julia"
        in_data = IOBuffer(in_string)
        enc_data = IOBuffer()

        cipher(enc_evp_cipher_ctx, in_data, enc_data)
        seek(enc_data, 0)
        @show String(read(enc_data))
        seek(enc_data, 0)

        dec_data = IOBuffer()
        cipher(dec_evp_cipher_ctx, enc_data, dec_data)
        out_data = take!(dec_data)
        out_string = String(out_data)

        @test in_string == out_string
    end
end

@testset "CipherKeyAndIVLengths" begin
    function encrypt_bytes(evp_cipher, key, iv, data)
        ctx = EvpCipherContext()
        encrypt_init(ctx, evp_cipher, key, iv)
        return vcat(OpenSSL.cipher_update(ctx, data), OpenSSL.cipher_final(ctx))
    end
    key = random_bytes(16)
    # an IV shorter than the cipher's is rejected rather than read past its end
    @test_throws ArgumentError encrypt_init(EvpCipherContext(), EvpAES128CBC(), key, UInt8[1])
    @test_throws ArgumentError decrypt_init(EvpCipherContext(), EvpAES128CBC(), key, UInt8[1])
    # a cipher with a fixed key length rejects another one
    @test_throws OpenSSL.OpenSSLError encrypt_init(EvpCipherContext(), EvpAES128CBC(), key[1:8], zeros(UInt8, 16))
    # Blowfish takes keys of other lengths, and uses all of their bytes. On OpenSSL 3 it
    # needs the legacy provider, which Julia's own OpenSSL build may not ship.
    blowfish = OpenSSL.version_number() < v"3" || try
        OpenSSL.load_provider("default")
        OpenSSL.load_legacy_provider()
        true
    catch
        false
    end
    if blowfish
        # Eric Young's test vector: key FFFFFFFFFFFFFFFF, plaintext FFFFFFFFFFFFFFFF
        @test bytes2hex(encrypt_bytes(EvpBlowFishECB(), fill(0xff, 8), UInt8[], fill(0xff, 8))[1:8]) ==
              "51866fd5b85ecb8a"
        long_key = collect(UInt8, 1:32)
        @test encrypt_bytes(EvpBlowFishCBC(), long_key, zeros(UInt8, 8), Vector{UInt8}("16 byte message!")) !=
              encrypt_bytes(EvpBlowFishCBC(), long_key[1:16], zeros(UInt8, 8), Vector{UInt8}("16 byte message!"))
    end
end

@testset "StackOf{X509Extension}" begin
    ext1 = X509Extension("subjectAltName", "DNS:openssl.jl.com")
    ext2 = X509Extension("keyUsage", "digitalSignature, keyEncipherment, keyAgreement")
    ext3 = X509Extension("basicConstraints", "CA:FALSE")

    st = StackOf{X509Extension}()
    push!(st, ext1)
    push!(st, ext2)
    push!(st, ext3)

    @test String(ext1) == "DNS:openssl.jl.com"
    @test String(ext2) == "Digital Signature, Key Encipherment, Key Agreement"
    @test String(ext3) == "CA:FALSE"

    finalize(ext1)
    finalize(ext2)
    finalize(ext3)

    @test length(st) == 3

    ext_1 = pop!(st)
    ext_2 = pop!(st)
    ext_3 = pop!(st)

    @test length(st) == 0

    @test String(ext_1) == "CA:FALSE"
    @test String(ext_2) == "Digital Signature, Key Encipherment, Key Agreement"
    @test String(ext_3) == "DNS:openssl.jl.com"

    finalize(ext_1)
    finalize(ext_2)
    finalize(ext_3)

    finalize(st)
end

@testset "SerializePrivateKey" begin
    evp_pkey = EvpPKey(rsa_generate_key())

    io = IOBuffer()
    n = write(io, evp_pkey)
    pkey_pem = String(take!(io))
    @test n == sizeof(pkey_pem)

    @test startswith(pkey_pem, "-----BEGIN PRIVATE KEY-----")

    _evp_pkey = EvpPKey(pkey_pem)

    @test _evp_pkey == evp_pkey

    # text ahead of the PEM block may be non-ASCII
    @test EvpPKey("friendlyName: Zoë Ünïcödé\n" * pkey_pem) == evp_pkey

    free(evp_pkey)
    free(_evp_pkey)
end

@testset "SerializePublicKey" begin
    evp_pkey = EvpPKey(rsa_generate_key())

    io = IOBuffer()
    n = OpenSSL.write_pubkey(io, evp_pkey)
    pubkey_pem = String(take!(io))
    @test n == sizeof(pubkey_pem)

    @test startswith(pubkey_pem, "-----BEGIN PUBLIC KEY-----")

    _evp_pkey = OpenSSL.read_pubkey(pubkey_pem)

    @test _evp_pkey == evp_pkey
end

@testset "DSA" begin
    evp_pkey = EvpPKey(dsa_generate_key())
    @test occursin("priv:", String(evp_pkey))

    # the generated pair signs a certificate, and verifies the signature
    x509_certificate = X509Certificate()
    x509_certificate.public_key = evp_pkey
    x509_name = X509Name()
    add_entry(x509_name, "CN", "dsa.example")
    x509_certificate.subject_name = x509_name
    x509_certificate.issuer_name = x509_name
    Dates.adjust(x509_certificate.time_not_before, Second(0))
    Dates.adjust(x509_certificate.time_not_after, Year(1))
    sign_certificate(x509_certificate, evp_pkey)
    @test x509_certificate.public_key == evp_pkey
end

@testset "EC" begin
    eckey = EvpPKey(OpenSSL.EC())
    @test eckey.key_type == OpenSSL.EVP_PKEY_EC
    free(eckey)

    @test_throws OpenSSL.OpenSSLError OpenSSL.ec_generate_key(Int32(-1))

    curves = OpenSSL.ec_builtin_curves()
    @test !isempty(curves)
    ec = OpenSSL.ec_generate_key(first(curves).id)
    @test ccall((:EC_KEY_check_key, OpenSSL.libcrypto), Cint, (OpenSSL.EC,), ec) == 1
    eckey = EvpPKey(ec)
    @test eckey.key_type == OpenSSL.EVP_PKEY_EC

    # a generated key can sign a certificate
    cert = X509Certificate()
    cert.public_key = eckey
    name = X509Name()
    add_entry(name, "CN", "ec.example")
    cert.subject_name = name
    cert.issuer_name = name
    Dates.adjust(cert.time_not_before, Second(0))
    Dates.adjust(cert.time_not_after, Year(1))
    sign_certificate(cert, eckey)
    @test occursin("/CN=ec.example", String(cert.subject_name))
    free(eckey)

    # curve ids can be any integer type
    @test OpenSSL.ec_generate_key(Int(first(curves).id)) isa OpenSSL.EC

    @test_throws ArgumentError OpenSSL.ec_generate_key("XXXX Non existing curve name XXXX")

    eckey = EvpPKey(OpenSSL.ec_generate_key("prime256v1"))
    @test eckey.key_type == OpenSSL.EVP_PKEY_EC
    free(eckey)
end

@testset "X509Attribute" begin
    attr = X509Attribute()
    free(attr)
end

@testset "SSLServer" begin
    server_ready = Threads.Event()
    server_task = @async test_server(server_ready)
    client_task = @async test_client(server_ready)
    # a failure in either task fails the testset; one side failing can leave the other
    # waiting for it, hence the timeout rather than a plain `fetch`
    tasks = (server_task, client_task)
    @test timedwait(() -> all(istaskdone, tasks), 60.0) === :ok
    for task in tasks
        @test istaskdone(task) && fetch(task) === nothing
    end
end

@testset "VersionNumber" begin
    vn = OpenSSL.version_number()
    @test vn ≥ v"1.1"

    m = match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", OpenSSL.version())
    major = parse(Int, m[1])
    minor = parse(Int, m[2])
    patch = parse(Int, m[3])
    vn2 = VersionNumber(major, minor, patch)
    if vn < v"3"
        # OpenSSL v1.1 uses non-conventional version numbers
        @test vn.major == vn2.major
        @test vn.minor == vn2.minor
    else
        @test vn == vn2
    end

    if vn ≥ v"3"
        # These only work with OpenSSL v3
        major = ccall((:OPENSSL_version_major, libcrypto), Cuint, ())
        minor = ccall((:OPENSSL_version_minor, libcrypto), Cuint, ())
        patch = ccall((:OPENSSL_version_patch, libcrypto), Cuint, ())
        vn3 = VersionNumber(major, minor, patch)
        @test vn == vn3
    end
end

@testset "CACertsLoading" begin
    certs_dir = joinpath(@__DIR__, "certs")
    certs_path = joinpath(certs_dir, "ca-certificates.crt")

    ssl_method = OpenSSL.TLSClientMethod()
    ctx = OpenSSL.SSLContext(ssl_method, certs_path)
    @test typeof(ctx) == OpenSSL.SSLContext
    ctx = OpenSSL.SSLContext(ssl_method, certs_dir)
    @test typeof(ctx) == OpenSSL.SSLContext

    @test_throws ErrorException OpenSSL.SSLContext(ssl_method, "does_not_exist")

end

@testset "TruncatedRecordEOF" begin
    # A peer that goes away in the middle of a record leaves a partial record buffered:
    # `haspending` stays true, `SSL_peek_ex` keeps asking for more bytes, and the socket
    # is at EOF. `eof` has to report the end of the stream rather than loop on that.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    server_task = @async eof(ssl)
    # keep taking whatever the server sends after the handshake (session tickets) off
    # the socket, so that closing it sends a FIN rather than a RST
    drain = @async while isopen(client.io)
        readavailable(client.io)
    end
    sleep(0.5)
    # a record header announcing 100 bytes, followed by only 3 of them, then close
    write(client.io, UInt8[0x17, 0x03, 0x03, 0x00, 0x64, 0xaa, 0xbb, 0xcc])
    close(client.io)
    @test timedwait(() -> istaskdone(drain), 5.0) === :ok
    # the spin never yields, so on one thread a hang here starves this task too: a
    # task that does not finish is reported by the timeout, a spinning one by CI
    @test timedwait(() -> istaskdone(server_task), 30.0) === :ok
    @test istaskdone(server_task) && fetch(server_task) === true
    close(client, false)
    close(ssl)
    close(server)
end

@testset "AcceptAfterClose" begin
    # `close` frees the SSL object, so `accept` on a closed stream has to stop before it
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client = Sockets.connect(ip"127.0.0.1", port)
    ssl = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSServerMethod(), ""), accept(server))
    close(ssl)
    @test_throws Base.IOError Sockets.accept(ssl)
    close(client)
    close(server)
end

@testset "ALPNByteLength" begin
    # the protocol list's length goes to OpenSSL in bytes: "\x03hé" is one 3-byte protocol
    ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), "")
    @test OpenSSL.ssl_set_alpn(ctx, "\x03hé") === nothing
    @test OpenSSL.ssl_set_alpn(ctx, OpenSSL.UPDATE_HTTP2_ALPN) === nothing
end

@testset "DistrustedKeys" begin
    fixtures = joinpath(@__DIR__, "emudhra")
    pem_certs(pem) = [X509Certificate(m.match) for m in
        eachmatch(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"s, pem)]

    intermediates = pem_certs(read(joinpath(fixtures, "intermediates.pem"), String))
    expected = readlines(joinpath(fixtures, "spki-sha256.txt"))
    @test length(intermediates) == length(expected) == 16
    for (cert, hash) in zip(intermediates, expected)
        spki = GC.@preserve cert OpenSSL.spki_sha256(cert.x509)
        @test bytes2hex(spki) == hash
        @test spki in OpenSSL.DISTRUSTED_SPKI_SHA256
    end
    leaf = first(pem_certs(read(joinpath(fixtures, "dv-g3b-emudhra.we-have-a-problem.com.pem"), String)))
    @test (GC.@preserve leaf OpenSSL.spki_sha256(leaf.x509)) ∉ OpenSSL.DISTRUSTED_SPKI_SHA256

    # A real handshake against a self-signed certificate that the client trusts. It must
    # succeed, then fail once the certificate's key is distrusted.
    evp_pkey = EvpPKey(rsa_generate_key())
    cert = X509Certificate()
    cert.public_key = evp_pkey
    name = X509Name()
    add_entry(name, "CN", "localhost")
    cert.subject_name = name
    cert.issuer_name = name
    Dates.adjust(cert.time_not_before, Second(0))
    Dates.adjust(cert.time_not_after, Year(1))
    add_extension(cert, X509Extension("basicConstraints", "CA:TRUE"))
    sign_certificate(cert, evp_pkey)
    ca_file, io = mktemp()
    write(io, cert)
    close(io)

    port, server = listenany(Sockets.localhost, 0)
    server_task = @async begin
        for _ in 1:2
            sock = accept(server)
            ctx = OpenSSL.SSLContext(OpenSSL.TLSServerMethod())
            OpenSSL.ssl_use_certificate(ctx, cert)
            OpenSSL.ssl_use_private_key(ctx, evp_pkey)
            ssl = SSLStream(ctx, sock)
            try
                # `OpenSSL.accept` does not wait when the handshake needs more data.
                while (ret = ccall((:SSL_accept, OpenSSL.libssl), Cint, (OpenSSL.SSL,), ssl.ssl)) != 1
                    OpenSSL.get_error(ssl.ssl, ret) == OpenSSL.SSL_ERROR_WANT_READ || break
                    eof(sock) && break
                end
                eof(ssl)
            catch
            finally
                close(sock)
            end
        end
    end
    function client_connect()
        ssl = SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ca_file), connect(Sockets.localhost, port))
        try
            OpenSSL.connect(ssl; require_ssl_verification=true)
        finally
            close(ssl)
        end
    end

    @test client_connect() === nothing
    spki = GC.@preserve cert OpenSSL.spki_sha256(cert.x509)
    push!(OpenSSL.DISTRUSTED_SPKI_SHA256, spki)
    try
        err = @catch_exception_object client_connect()
        @test err isa OpenSSL.OpenSSLError
        @test occursin("distrusted public key", err.msg)
    finally
        delete!(OpenSSL.DISTRUSTED_SPKI_SHA256, spki)
    end
    wait(server_task)
    close(server)
    rm(ca_file)
end

@testset "WriteCallbackFailure" begin
    # The socket write inside the BIO callback fails (here: the socket is closed). The
    # SSL call has to fail with it, rather than report the bytes written.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    close(client.io)
    err = @test_throws Base.IOError write(client, UInt8[1, 2, 3])
    @test !isopen(client)
    # the failure is the socket write's own, made after the SSL call: `write` reports it
    # and nothing is left on the thread's error queue for an unrelated call to report
    @test occursin("closed", sprint(showerror, err.value))
    @test ccall((:ERR_peek_error, OpenSSL.libcrypto), Culong, ()) == 0
    close(ssl, false)
    close(server)
end

@testset "RawWriteFailure" begin
    # the same failure from a raw call on `ssl.ssl`: the callback's -1 fails the call
    # with SSL_ERROR_SYSCALL
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    close(client.io)
    payload = UInt8[1, 2, 3]
    n = Ref{Csize_t}(0)
    ret = Base.@lock client.lock GC.@preserve payload ccall(
        (:SSL_write_ex, OpenSSL.libssl),
        Cint,
        (OpenSSL.SSL, Ptr{Cvoid}, Csize_t, Ptr{Csize_t}),
        client.ssl, pointer(payload), length(payload), n)
    @test ret == 0
    @test OpenSSL.get_error(client.ssl, ret) == OpenSSL.SSL_ERROR_SYSCALL
    # OpenSSL 3.2 and later also leave their account of it on the error queue
    # (`tls_retry_write_records failure`), as for any failed raw call; older versions
    # record nothing for a SYSCALL error. Either way the queue is the raw caller's to
    # read or clear
    if OpenSSL.version_number() >= v"3.2"
        @test ccall((:ERR_peek_error, OpenSSL.libcrypto), Culong, ()) != 0
    end
    OpenSSL.clear_errors!()
    close(client, false)
    close(ssl, false)
    close(server)
end

@testset "CloseAfterSocketGone" begin
    # `close(ssl)` with the socket already gone: the close_notify write fails, which
    # fails SSL_shutdown; OpenSSL 3.2+ records that on the thread's error queue and
    # `close` clears it, so an unrelated call later does not report it
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    close(client.io)
    OpenSSL.clear_errors!()
    close(client)
    @test !isopen(client)
    @test ccall((:ERR_peek_error, OpenSSL.libcrypto), Culong, ()) == 0
    close(ssl, false)
    close(server)
end

@testset "ConcurrentWriters" begin
    # Several tasks writing to one stream, each with its own chunk size: the byte count
    # `SSL_write_ex` reports has to be the one of this task's call, not of whichever
    # task ran last on the stream, or a writer resubmits bytes already sent. Every size
    # is more than what goes to OpenSSL in one call: a write still arrives in one piece.
    nwriters = 4
    nchunks = 16
    chunklen(id) = Int(OpenSSL.SSL_WRITE_CHUNK) + id * 32 * 1024
    total = sum(nchunks * chunklen(id) for id in 1:nwriters)

    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    server_task = @async begin
        received = Vector{UInt8}(undef, total)
        read!(ssl, received)
        received
    end

    writers = map(1:nwriters) do id
        @async begin
            chunk = fill(UInt8(id), chunklen(id))
            for _ in 1:nchunks
                write(client, chunk)
            end
        end
    end
    @test timedwait(() -> all(istaskdone, writers), 60.0) === :ok
    @test !any(istaskfailed, writers)
    @test timedwait(() -> istaskdone(server_task), 60.0) === :ok
    if istaskdone(server_task) && !istaskfailed(server_task)
        received = fetch(server_task)
        @test length(received) == total
        # every writer's bytes all arrived, whatever the interleaving
        for id in 1:nwriters
            @test count(==(UInt8(id)), received) == nchunks * chunklen(id)
        end
        # and each write in one piece: a run of one writer's byte is whole writes long
        @test wholewrites(received, chunklen)
    else
        @test false
    end
    close(client)
    close(ssl, false)
    close(server)
end

@testset "ConcurrentReadWrite" begin
    # A write that is waiting for the peer must not stop reads on the same stream:
    # `SSL_write_ex` and `SSL_read_ex` share `ssl.lock`, so the socket write the write
    # BIO does has to happen outside it (#72).
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    payload = collect(0x01:0x40)
    write(ssl, payload)
    # and from here on the server reads nothing, so the client's write parks

    stop_writing = Threads.Atomic{Bool}(false)
    writer, _ = park_writer(client, stop_writing)
    # the write waits for the socket without holding the lock reads need
    @test timedwait(() -> !islocked(client.lock), 5.0) === :ok

    buff = Vector{UInt8}(undef, length(payload))
    reader = @async read!(client, buff)
    @test boundedfetch(reader, :stalled) == payload

    # the client still has megabytes parked against a peer that is not reading: its
    # close cuts that write off, which fails the writer. On a task: should the close
    # wait for that write (as it did before this fix) the test fails, not the suite
    stop_writing[] = true
    closer = @async close(client)
    @test timedwait(() -> istaskdone(closer), 30.0) === :ok
    istaskdone(closer) || OpenSSL.forceclose!(client.io)
    @test timedwait(() -> istaskdone(writer), 30.0) === :ok
    @test istaskdone(writer) && fetch(writer) isa Base.IOError
    close(ssl, false)
    close(server)
end

@testset "FullDuplex" begin
    # Both ends write more than the socket buffers hold while reading what the other
    # writes: with the socket write under `ssl.lock` both writers park and neither reader
    # can run, so nothing finishes.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    n = 8 * 2^20
    c2s = rand(UInt8, n)
    s2c = rand(UInt8, n)
    tasks = [
        @async(write(client, c2s)),
        @async(write(ssl, s2c)),
        @async(read!(client, Vector{UInt8}(undef, n))),
        @async(read!(ssl, Vector{UInt8}(undef, n))),
    ]
    done = timedwait(() -> all(istaskdone, tasks), 120.0) === :ok
    @test done
    if done
        @test !any(istaskfailed, tasks)
        @test fetch(tasks[3]) == s2c
        @test fetch(tasks[4]) == c2s
    else
        # release what stalled rather than leave it to outlast the testset
        OpenSSL.forceclose!(client.io)
        OpenSSL.forceclose!(ssl.io)
    end
    close(client)
    close(ssl)
    close(server)
end

@testset "CloseWithParkedWriter" begin
    # `close` while a write is parked on a peer that stopped reading: the close does not
    # wait for that write, which could be forever; it closes the socket outright, which
    # fails the writer.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    stop_writing = Threads.Atomic{Bool}(false)
    writer, written = park_writer(client, stop_writing)
    stop_writing[] = true
    t0 = time()
    close(client)
    @test time() - t0 < 5.0
    @test !isopen(client)
    @test timedwait(() -> istaskdone(writer), 30.0) === :ok
    @test istaskdone(writer) && fetch(writer) isa Base.IOError
    # the server reaches the end of the stream, however much of the write got through
    reader = @async try
        while !eof(ssl)
            readavailable(ssl)
        end
        :eof
    catch ex
        ex
    end
    outcome = boundedfetch(reader, :stalled)
    @test outcome !== :stalled
    outcome === :stalled && OpenSSL.forceclose!(ssl.io)
    close(ssl, false)
    close(server)
end

@testset "CloseRacingWriter" begin
    # a write whose socket write completed just as `close` ran: the writer returns
    # success, since its bytes did reach the socket, and the peer reads them all
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    # one read on the client first, so that the server's session tickets do not sit
    # unread in its socket: closing a socket with unread data resets the connection,
    # and on Windows the reset discards what the peer has not read yet
    write(ssl, UInt8[0x01])
    @test read!(client, Vector{UInt8}(undef, 1)) == UInt8[0x01]
    payload = rand(UInt8, 1000)
    writer = @async try
        write(client, payload)
        :ok
    catch ex
        ex
    end
    closer = @async close(client)
    @test boundedfetch(writer, :stalled) === :ok
    @test boundedfetch(closer, :stalled) === nothing
    reader = @async read!(ssl, Vector{UInt8}(undef, length(payload)))
    @test boundedfetch(reader, :stalled) == payload
    close(ssl, false)
    close(server)
end

@testset "CloseBehindRawWrite" begin
    # `close` with the socket's send buffer full of a raw write (one not made through the
    # stream, so nothing is in flight for `close` to cut): the close_notify's socket
    # write would park behind it forever, so after a grace period the socket is closed
    # outright, and the stream's `sendlock` is released
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    # written until it parks: one write, however large, may not (Windows takes a whole
    # 64 MiB with no reader)
    stop_writing = Threads.Atomic{Bool}(false)
    raw, _ = park_writer(client, stop_writing; io=client.io)
    stop_writing[] = true
    t0 = time()
    close(client)
    @test time() - t0 < 1.0
    @test timedwait(() -> istaskdone(raw), OpenSSL.CLOSE_NOTIFY_GRACE + 30.0) === :ok
    @test timedwait(() -> !isopen(client.io), 30.0) === :ok
    @test timedwait(() -> !islocked(client.sendlock), 30.0) === :ok
    close(ssl, false)
    close(server)
end

@testset "CloseBehindRawWriteNoShutdown" begin
    # the same, for a close that makes no close_notify (`close(ssl, false)`, which the
    # failed-call path uses): nothing is buffered to send, but Base's own socket close
    # waits behind the parked write, so that too is bounded
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    stop_writing = Threads.Atomic{Bool}(false)
    raw, _ = park_writer(client, stop_writing; io=client.io)
    stop_writing[] = true
    t0 = time()
    close(client, false)
    @test time() - t0 < 1.0
    @test timedwait(() -> istaskdone(raw), OpenSSL.CLOSE_NOTIFY_GRACE + 30.0) === :ok
    @test timedwait(() -> !isopen(client.io), 30.0) === :ok
    @test timedwait(() -> !islocked(client.sendlock), 30.0) === :ok
    close(ssl, false)
    close(server)
end

@testset "FinalizerClosesInPlace" begin
    # the finalizer closes the socket itself, without starting a task (Julia runs
    # finalizers at exit, when a task another thread starts can crash the process), and
    # leaves a stream whose lock is held to a later collection rather than wait for it
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    lock(client.lock)
    finalize(client)
    @test isopen(client)
    unlock(client.lock)
    finalize(client)
    @test !isopen(client)
    @test client.io.status in (Base.StatusClosing, Base.StatusClosed)
    close(ssl, false)
    close(server)
end

@testset "StreamMethodOutlivesFinalizers" begin
    # Julia runs every finalizer at exit while other threads may still create and free
    # streams, so the BIO method all streams share must not be freed by one: a stream
    # made after it would use the freed method. `finalize` runs what exit would run.
    script = """
        using OpenSSL, Sockets
        finalize(OpenSSL.BIO_STREAM_METHOD.x)
        s = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""), TCPSocket())
        OpenSSL.free(s.ssl)
        """
    cmd = `$(Base.julia_cmd()) --startup-file=no --project=$(Base.active_project()) -e $script`
    @test success(ignorestatus(cmd))
end

@testset "CloseNotifyEOF" begin
    # the peer's close_notify, sent by `close`, surfaces from `eof` as the "unexpected
    # EOF" `IOError` and closes the stream; and it follows the writes made before the
    # close, which the peer reads first
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    # the client reads too, which takes the server's session tickets off its socket:
    # closed with them unread, the kernel may reset the connection rather than end it
    # (Windows does), and the peer lose the close_notify to the reset
    client_reader = @async try
        while !eof(client)
            readavailable(client)
        end
    catch
    end
    payload = rand(UInt8, 100_000)
    write(client, payload)
    sleep(0.2)
    close(client)
    reader = @async begin
        received = read!(ssl, Vector{UInt8}(undef, length(payload)))
        err = try
            eof(ssl)
            nothing
        catch ex
            ex
        end
        (received, err)
    end
    outcome = boundedfetch(reader, :stalled)
    @test outcome !== :stalled
    if outcome !== :stalled
        received, err = outcome
        @test received == payload
        @test err isa Base.IOError
        @test occursin("unexpected EOF", sprint(showerror, err))
        @test !isopen(ssl)
    else
        OpenSSL.forceclose!(ssl.io)
    end
    @test timedwait(() -> istaskdone(client_reader), 30.0) === :ok
    close(ssl)
    close(server)
end

@testset "WriteSizes" begin
    # the peer reads every write whole and in order, across sizes around a record's and
    # a write of many records
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    payloads = [rand(UInt8, n) for n in (1, 100, 16383, 16384, 16385, 50_000, 2^20 + 7, 3)]
    expected = reduce(vcat, payloads)
    reader = @async read!(ssl, Vector{UInt8}(undef, length(expected)))
    for payload in payloads
        write(client, payload)
    end
    @test boundedfetch(reader, :stalled) == expected
    # nothing left buffered, and nothing kept
    @test isempty(client.data.buf)
    close(client)
    close(ssl)
    close(server)
end

@testset "ReplyBehindSender" begin
    # a reply a read produced goes out from a task when `sendlock` is free; when a sender
    # holds the lock, that sender sends it before releasing the lock, so it is not lost
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    # the server's socket read raw: what the client's write BIO sent, as it is
    marker1 = rand(UInt8, 16)
    marker2 = rand(UInt8, 16)
    # the lock is free: the reply task sends
    got1 = @async read(ssl.io, 16)
    Base.@lock client.lock append!(client.data.buf, marker1)
    OpenSSL.sendreply!(client)
    @test boundedfetch(got1, :stalled) == marker1
    # the lock is taken: the reply task leaves the reply to the holder
    got2 = @async read(ssl.io, 16)
    lock(client.sendlock)
    Base.@lock client.lock append!(client.data.buf, marker2)
    OpenSSL.sendreply!(client)
    sleep(0.3)
    @test !istaskdone(got2)
    @test !isempty(client.data.buf)
    # what every holder does before releasing the lock
    OpenSSL.drainlocked!(client)
    @test !islocked(client.sendlock)
    @test boundedfetch(got2, :stalled) == marker2
    close(client, false)
    close(ssl, false)
    close(server)
end

@testset "LegacyAccept" begin
    # `accept` keeps its contract: one round, which does not wait for the peer, so the
    # deadline a loop checks between calls holds against a peer that stays silent
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    silent = Sockets.connect(ip"127.0.0.1", port)
    ssl = OpenSSL.SSLStream(server_ctx, accept(server))
    # the loop written to `accept`'s contract: one round per call, `OpenSSLError` when
    # it needs more bytes, the wait for them and the deadline between calls
    function acceptloop(ssl, deadline)
        rounds = 0
        while true
            try
                Sockets.accept(ssl)
                return :ok, rounds
            catch ex
                ex isa OpenSSL.OpenSSLError || rethrow()
                rounds += 1
                time() < deadline || return :deadline_expired, rounds
                arrival = @async eof(ssl.io)
                timedwait(() -> istaskdone(arrival), max(deadline - time(), 0.01))
            end
        end
    end
    outcome, rounds = acceptloop(ssl, time() + 0.5)
    @test outcome === :deadline_expired
    @test rounds >= 1
    # nothing failed: the loop could have gone on
    @test isopen(ssl)
    # no close_notify from a handshake in progress, which would queue an error
    close(ssl, false)
    close(silent)
    close(server)
end

@testset "RawSSLCalls" begin
    # a call made on `ssl.ssl` from outside the package writes to the socket from the
    # write BIO callback itself, as before: an `SSL_accept` loop of a caller's own (under
    # `ssl.lock`, as TLSStreams runs it) completes the handshake, and a raw write lands
    # whole among the records of a parked write, nothing lost
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client_task = connecting(port)
    ssl = OpenSSL.SSLStream(server_ctx, accept(server))
    deadline = time() + 30.0
    while true
        done = Base.@lock ssl.lock begin
            try
                OpenSSL.ssl_accept(ssl.ssl)
                true
            catch ex
                ex isa OpenSSL.OpenSSLError || rethrow()
                false
            end
        end
        done && break
        time() < deadline || error("the raw accept loop did not finish")
        eof(ssl.io) && error("the peer went away during the raw accept loop")
    end
    client = fetch(client_task)
    write(client, UInt8[1, 2, 3])
    @test read!(ssl, Vector{UInt8}(undef, 3)) == UInt8[1, 2, 3]

    # the server reads nothing for now, so the client's writer parks; a raw write on the
    # client then goes straight to the socket, behind the record in libuv
    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, written = park_writer(client, stop_writing)
    stop_writing[] = true
    nzeros = written[] + PARK_CHUNK
    marker = fill(UInt8(7), 100)
    raw = @async Base.@lock client.lock begin
        n = Ref{Csize_t}(0)
        r = GC.@preserve marker ccall(
            (:SSL_write_ex, OpenSSL.libssl),
            Cint,
            (OpenSSL.SSL, Ptr{Cvoid}, Csize_t, Ptr{Csize_t}),
            client.ssl, pointer(marker), length(marker), n)
        (r, Int(n[]))
    end
    reader = @async read!(ssl, Vector{UInt8}(undef, nzeros + length(marker)))
    received = boundedfetch(reader, :stalled; timeout=60.0)
    @test received isa Vector{UInt8}
    if received isa Vector{UInt8}
        @test count(==(0), received) == nzeros
        sevens = findall(==(7), received)
        @test length(sevens) == length(marker)
        # in one piece
        @test !isempty(sevens) && sevens == sevens[1]:sevens[1] + length(marker) - 1
    else
        OpenSSL.forceclose!(client.io)
    end
    @test boundedfetch(raw, :stalled) == (1, 100)
    @test boundedfetch(parked_writer, :stalled) === nothing
    close(client)
    close(ssl)
    close(server)
end

@testset "PeerResetMidRecord" begin
    # a peer that resets the connection mid-record: `eof` reports the error or the end
    # of the stream, and so does the next `eof`, rather than hang
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    reader = @async try
        eof(ssl)
    catch ex
        ex
    end
    # a partial record, then a close with the session tickets the server sent still
    # unread, which makes the kernel reset the connection rather than end it
    sleep(0.2)
    write(client.io, UInt8[0x17, 0x03, 0x03, 0x00, 0x64, 0xaa, 0xbb, 0xcc])
    close(client.io)
    outcome = boundedfetch(reader, :stalled)
    @test outcome isa Base.IOError || outcome === true
    outcome === :stalled && OpenSSL.forceclose!(ssl.io)
    again = @async try
        eof(ssl)
    catch ex
        ex
    end
    outcome = boundedfetch(again, :stalled)
    @test outcome isa Base.IOError || outcome === true
    outcome === :stalled && OpenSSL.forceclose!(ssl.io)
    close(client, false)
    close(ssl, false)
    close(server)
end

@testset "FatalAlertReachesPeer" begin
    # a forged record fails the server's read; the alert OpenSSL produces while failing
    # is buffered, since the call runs under `ssl.lock`, and the `close` that the failure
    # makes sends it, so the peer learns why instead of seeing a clean end of stream
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    forged = UInt8[0x17, 0x03, 0x03, 0x00, 0x20]
    append!(forged, rand(UInt8, 0x20))
    write(client.io, forged)
    server_read = @async try
        eof(ssl)
    catch ex
        ex
    end
    outcome = boundedfetch(server_read, :stalled)
    @test outcome isa Base.IOError
    @test !isopen(ssl)
    client_read = @async try
        eof(client)
    catch ex
        ex
    end
    outcome = boundedfetch(client_read, :stalled)
    @test outcome isa Base.IOError
    @test outcome isa Base.IOError && occursin("alert", outcome.msg)
    close(client, false)
    close(ssl, false)
    close(server)
end
