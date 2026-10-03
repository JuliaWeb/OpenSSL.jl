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

    # the bundle is Mozilla's root list and its order changes with it, so pick a
    # certificate that carries the fields under test rather than trusting an index
    has_ou(cert) = occursin("/OU=", String(cert.subject_name))
    x509_cert = nothing
    for pem in certs_pem
        occursin("-----BEGIN CERTIFICATE-----", pem) || continue
        candidate = X509Certificate(pem)
        if has_ou(candidate)
            x509_cert = candidate
            break
        end
    end
    @test x509_cert !== nothing
    # the rest only with a certificate to look at, a failure rather than an error
    # otherwise
    if x509_cert !== nothing
        @test occursin("/C=", String(x509_cert.subject_name))
        @test occursin("/OU=", String(x509_cert.subject_name))
        @test  occursin("/CN=", String(x509_cert.subject_name))

        # the roots in the bundle are self signed, so the issuer carries the same fields
        @test occursin("/C=", String(x509_cert.issuer_name))
        @test occursin("/OU=", String(x509_cert.issuer_name))
        @test  occursin("/CN=", String(x509_cert.issuer_name))

        s_before_time = replace(String(x509_cert.time_not_before), r" +" => " ")
        @test DateTime(s_before_time, dateformat"u d HH:MM:SS yyyy Z") < today()

        s_after_time = replace(String(x509_cert.time_not_after), r" +" => " ")
        @test DateTime(s_after_time, dateformat"u d HH:MM:SS yyyy Z") > today()
    end

    # finalizer will cleanup
    #finalize(x509_cert)
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
    res = digest(EvpMD5(), IOBuffer("The quick brown fox jumps over the lazy dog"))
    @test res == UInt8[0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6]
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

    port, server = Sockets.listenany(10000)
    iob = connect(port)
    sob = accept(server)
    local cert_pem
    try
        write(iob, x509_certificate)
        cert_pem = String(readavailable(sob))
    finally
        close(iob)
        close(sob)
        close(server)
    end

    x509_certificate2 = X509Certificate(cert_pem)

    x509_string = String(x509_certificate)
    x509_string2 = String(x509_certificate2)

    public_key = x509_certificate.public_key

    @test x509_string == x509_string2

    p12_object = P12Object(evp_pkey, x509_certificate)

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
    x509_request.version = 0
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

    port, server = Sockets.listenany(10000)
    iob = connect(port)
    sob = accept(server)
    local pkey_pem
    try
        write(iob, evp_pkey)
        pkey_pem = String(readavailable(sob))
    finally
        close(iob)
        close(sob)
        close(server)
    end

    @test startswith(pkey_pem, "-----BEGIN PRIVATE KEY-----")

    _evp_pkey = EvpPKey(pkey_pem)

    @test _evp_pkey == evp_pkey

    free(evp_pkey)
    free(_evp_pkey)
end

@testset "DSA" begin
    dsa = dsa_generate_key()
end

@testset "X509Attribute" begin
    attr = X509Attribute()
    free(attr)
end

@testset "SSLServer" begin
    server_ready = Threads.Condition()
    server_task = @async test_server(server_ready)
    client_task = @async test_client(server_ready)
    if isdefined(Base, :errormonitor)
        errormonitor(server_task)
        errormonitor(client_task)
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

# a server context with a self-signed certificate for localhost
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

# a connected client and the task running the server side of the handshake, which
# returns the server's `SSLStream`
function connected_pair(server_ctx, server)
    server_task = @async begin
        ssl = OpenSSL.SSLStream(server_ctx, accept(server))
        Sockets.accept(ssl; timeout=Inf)
        ssl
    end
    port = Sockets.getsockname(server)[2]
    client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
        Sockets.connect(ip"127.0.0.1", port))
    Sockets.connect(client; require_ssl_verification=false)
    return client, fetch(server_task)
end

# runs `f(kept)` with the chunks kept for `client`'s socket collected into `kept`, a
# vector under `lock`; whatever other tasks keep meanwhile is left out
function withkept(f, client)
    kept = Any[]
    keptlock = ReentrantLock()
    OpenSSL.ONKEEP[] = (io, chunk) -> io === client.io && Base.@lock(keptlock, push!(kept, chunk))
    try
        return f(() -> Base.@lock(keptlock, copy(kept)))
    finally
        OpenSSL.ONKEEP[] = nothing
    end
end

# waits for `task`, a read of the server stream `ssl`, under a deadline: its outcome
# (see `taskoutcome`), or `:stalled` should it not finish, both streams then aborted and
# the client's socket cut, each whatever the one before it throws, so that the read is
# released and nothing hangs the suite. The verdict is the caller's to assert, so that a
# failure names the call
function awaitread(task, ssl, client; timeout=30.0, onstall=nothing)
    timedwait(() -> istaskdone(task), timeout) === :ok && return taskoutcome(task)
    try
        # what the caller would know of the stall before the abort changes it
        onstall === nothing || onstall()
    finally
        try
            close(ssl, false)
        finally
            try
                close(client, false)
            finally
                OpenSSL.cut!(client.data)
            end
        end
    end
    return :stalled
end

# a finished task's value, or, should it have failed, the exception it failed with (not
# the TaskFailedException `fetch` wraps it in), for the caller to assert on rather than
# to be thrown out of the testset by
taskoutcome(task) = istaskfailed(task) ? task.result : fetch(task)

# `task`'s outcome (see `taskoutcome`) should it finish within `timeout`, else
# `placeholder`: the verdict is the caller's to assert, and nothing waits on a task that
# stalled
boundedfetch(task, placeholder; timeout=30.0) =
    timedwait(() -> istaskdone(task), timeout) === :ok ? taskoutcome(task) : placeholder

# `f`, a read of the server stream `ssl` catching its own errors, on a task of its own,
# waited for as `awaitread` does
boundedread(f, ssl, client; kwargs...) = awaitread(@async(f()), ssl, client; kwargs...)

# for a test whose `client` the caller has closed and whose `reader` reads `ssl`: waits
# for the read as `awaitread` does, runs `check` on its outcome should it have finished,
# and closes `ssl` gracefully whatever `check` or the read's own failure throws. The
# client's socket is checked to have closed of itself either way: after the check, or,
# should the read stall, before the abort closes it. It is cut last, which is bounded (a
# normal close could wait for a close that never comes), so that nothing of the pair
# outlasts the testset
function awaitpeer(check, reader, ssl, client)
    closedofitself() = @test timedwait(() -> !isopen(client.io), 10.0) === :ok
    stalled = false
    try
        r = awaitread(reader, ssl, client; onstall=closedofitself)
        stalled = r === :stalled
        @test !stalled
        if !stalled
            try
                check(r)
            finally
                closedofitself()
            end
        end
    finally
        try
            # aborted already, should the read have stalled
            stalled || close(ssl)
        finally
            OpenSSL.cut!(client.data)
        end
    end
    return
end

# writes until the peer's receive window is full and the writer parks on the socket;
# returns the task and the count of completed writes. Each write is many times what goes
# to OpenSSL in one call, so that the parked one has records still to make, and more
# than the kernel's send and receive buffers grow to (Windows and macOS keep growing
# them for a peer that does not read): a parked write that the buffers could still take
# would complete of itself, and the tests need it to stay parked until they end it. One
# record of it, the one in libuv, may still be accepted as the buffers grow, which is
# all the Base race described at CancelledInFlightWriter needs
const PARK_CHUNK = max(32 * 2^20, 3 * OpenSSL.SSL_WRITE_CHUNK)
function park_writer(client, stop_writing)
    written = Threads.Atomic{Int}(0)
    chunk = zeros(UInt8, PARK_CHUNK)
    writer = @async try
        while !stop_writing[]
            write(client, chunk)
            Threads.atomic_add!(written, length(chunk))
        end
        nothing
    catch ex
        ex
    end
    # parked means: bytes handed to libuv that have not left for the kernel, the same
    # amount half a second later, and no write completed meanwhile. A writer that is
    # merely slow, mid-encryption say, has nothing queued in libuv
    queued() = OpenSSL.writequeuesize(client.io)
    parked = timedwait(60.0; pollint=0.5) do
        before = (written[], queued())
        sleep(0.5)
        !istaskdone(writer) && before[2] > 0 && (written[], queued()) == before
    end
    # nothing that follows makes sense without a parked writer, and cancelling one that
    # is running is not allowed: stop here rather than fail all down the line
    if parked !== :ok
        outcome = istaskdone(writer) ? fetch(writer) : "still writing"
        close(client, false)
        error("the writer did not park on the socket: $outcome")
    end
    return writer, written
end

# whether every run of one writer's byte in `received` is whole writes of that writer long
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

@testset "ConcurrentReadWrite" begin
    # A write that is waiting for the peer must not stop reads on the same stream:
    # `SSL_write_ex` and `SSL_read_ex` share `ssl.lock`, so the socket write the write
    # BIO does has to happen outside it.
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
    reader = @async try
        read!(client, buff)
    catch ex
        ex
    end
    @test timedwait(() -> istaskdone(reader), 30.0) === :ok
    @test buff == payload

    # the server has to go away first: the client still has megabytes parked against a
    # peer that is not reading, so its own close cannot finish until that write fails
    stop_writing[] = true
    close(ssl)
    close(client)
    close(server)
    @test timedwait(() -> istaskdone(writer), 30.0) === :ok
end

@testset "ConcurrentWriters" begin
    # Several tasks writing to one stream: each SSL call takes its own ciphertext under
    # `ssl.lock` and the socket writes go out in that order, so the records arrive in
    # the order OpenSSL made them (out of order would fail the record MAC on the peer)
    # and neither writer returns before its own bytes reached the socket.
    # Different sizes per writer: the byte count `SSL_write_ex` reports has to be the
    # one of this task's call, not of whichever task ran last on the stream. And all
    # larger than what goes to OpenSSL in one call: a write still arrives in one piece.
    nwriters = 4
    nchunks = 4
    chunklen(id) = OpenSSL.SSL_WRITE_CHUNK + id * (OpenSSL.SSL_WRITE_CHUNK ÷ 2)
    total = sum(nchunks * chunklen(id) for id in 1:nwriters)

    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    server_task = @async begin
        received = Vector{UInt8}(undef, total)
        read!(ssl, received)
        close(ssl)
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
    received = boundedfetch(server_task, :stalled; timeout=60.0)
    @test received isa Vector{UInt8}
    # a read that stalled or failed released, rather than left to outlast the testset
    received isa Vector{UInt8} || close(ssl, false)
    if received isa Vector{UInt8}
        @test length(received) == total
        # every writer's bytes all arrived, whatever the interleaving
        for id in 1:nwriters
            @test count(==(UInt8(id)), received) == nchunks * chunklen(id)
        end
        # and each write in one piece: a run of one writer's byte is whole writes long
        @test wholewrites(received, chunklen)
    end
    close(client)
    close(server)
end

@testset "CancelledCloser" begin
    # A close cancelled while it waits for a parked writer, issued before it, to be
    # through must leave nothing hanging: the stream is aborted, which fails the parked
    # write. A writer issued after the close is refused at once, not kept waiting.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    # the server reads nothing, so the client's writer parks on the socket

    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, _ = park_writer(client, stop_writing)
    stop_writing[] = true

    closer = @async close(client)
    third_writer = @async try
        write(client, UInt8[2])
    catch ex
        ex
    end
    # the closer has to be blocked before it is cancelled: delivering an exception to a
    # task that is running is not allowed. Tasks made here run on this thread, so once
    # this one runs again the closer is blocked, waiting for the parked writer
    sleep(0.2)
    @test !istaskdone(closer)
    @test isopen(client)
    # issued after the close began: refused already
    @test istaskdone(third_writer) && fetch(third_writer) isa Base.IOError
    schedule(closer, InterruptException(); error=true)
    @test timedwait(() -> istaskdone(closer), 5.0) === :ok
    @test istaskfailed(closer)
    # the close was given up half way, so the stream is aborted: that fails the parked
    # write, without the server having to do anything
    @test !isopen(client)
    @test timedwait(() -> istaskdone(parked_writer), 30.0) === :ok
    @test istaskdone(parked_writer) && fetch(parked_writer) isa Exception
    @test timedwait(() -> !isopen(client.io), 30.0) === :ok
    close(ssl)
    close(server)
end

# `closewrite` on a socket needs Julia 1.8
if VERSION >= v"1.8"
@testset "TruncatedRecordEOF" begin
    # A peer that goes away in the middle of a record leaves a partial record buffered:
    # `haspending` stays true, `SSL_peek_ex` keeps asking for more bytes, and the socket
    # is at EOF. `eof` has to report the end of the stream rather than loop on that.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    server_task = @async eof(ssl)

    # a record header announcing 100 bytes, followed by only 3 of them, then a FIN. Only
    # the write side: closing the socket with the session tickets the server sent
    # after the handshake still unread would send a RST instead
    write(client.io, UInt8[0x17, 0x03, 0x03, 0x00, 0x64, 0xaa, 0xbb, 0xcc])
    closewrite(client.io)

    # the spin never yields, so on one thread a hang here would starve this task too;
    # a task that does not finish is reported by the timeout, a spinning one by CI
    @test timedwait(() -> istaskdone(server_task), 30.0) === :ok
    @test istaskdone(server_task) && fetch(server_task) === true
    # and, as `eof` on a socket, it does not close the stream: the peer may have shut
    # down its side only, and a reply may still be due
    @test isopen(ssl)
    close(client)
    close(ssl)
    close(server)
end
end

@testset "VerifyFailureCloses" begin
    # a peer whose certificate does not verify: the error is what it was, the stream is
    # closed rather than left usable
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    server_task = @async begin
        ssl = OpenSSL.SSLStream(server_ctx, accept(server))
        try
            Sockets.accept(ssl; timeout=Inf)
        catch
        end
        close(ssl)
    end
    client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod()),
        Sockets.connect(ip"127.0.0.1", port))
    @test_throws OpenSSL.OpenSSLError Sockets.connect(client)
    @test !isopen(client)
    @test timedwait(() -> istaskdone(server_task), 10.0) === :ok
    close(server)
end

@testset "SocketErrorCloses" begin
    # a peer that resets the connection mid-record: the error from the socket ends the
    # stream, so the next call does not run into it again
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    server_task = @async try
        eof(ssl)
    catch ex
        ex
    end
    # a partial record, then a close with the session tickets the server sent still
    # unread, which makes the kernel reset the connection rather than end it
    sleep(0.2)
    write(client.io, UInt8[0x17, 0x03, 0x03, 0x00, 0x64, 0xaa, 0xbb, 0xcc])
    close(client.io)
    outcome = awaitread(server_task, ssl, client)
    @test outcome !== :stalled
    if outcome !== :stalled
        # on Linux a close with inbound bytes unread is a reset for sure; elsewhere it
        # may be a FIN, which is the end of the stream and nothing more
        Sys.islinux() && @test outcome isa Base.IOError
        if outcome isa Base.IOError
            @test !isopen(ssl)
            # and the error is not run into again: the stream is simply at its end
            @test eof(ssl) === true
        else
            @test outcome === true
        end
    end
    close(client)
    close(ssl)
    close(server)
end

@testset "CloseNotifyEOF" begin
    # the peer's close_notify surfaces from `eof` as the "unexpected EOF" `IOError`, and
    # closes the stream. The peek that sees it produces nothing to send, but the error
    # path after the lock is released has to see the peek's result.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    # the client reads first, which takes the server's session tickets off its socket:
    # closed with them unread, the kernel may reset the connection rather than end it
    # (Windows does), and the peer lose the close_notify to the reset
    client_reader = @async try
        while !eof(client)
            readavailable(client)
        end
    catch
    end
    sleep(0.2)
    @test timedwait(() -> bytesavailable(client.io) == 0, 10.0) === :ok
    close(client)
    err = boundedread(ssl, client) do
        try
            eof(ssl)
            nothing
        catch ex
            ex
        end
    end
    @test err !== :stalled
    if err !== :stalled
        @test err isa Base.IOError
        @test occursin("unexpected EOF", sprint(showerror, err))
        @test !isopen(ssl)
    end
    close(ssl)
    close(server)
end

@testset "CloseWithQueuedWriter" begin
    # `close` started while a writer is parked and another waits behind it: both were
    # issued first, so both finish, the parked one's remaining chunk included, and the
    # close_notify follows their records: the peer reads them all and then the
    # close_notify, not a gap or a cut write.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    # the client reads too, which takes the server's session tickets off its socket:
    # closed with them unread, the kernel resets the connection rather than ending it,
    # and the peer loses what it had not read yet of the writes, and the close_notify
    client_reader = @async try
        while !eof(client)
            readavailable(client)
        end
    catch
    end

    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, written = park_writer(client, stop_writing)
    stop_writing[] = true
    queued_writer = @async try
        write(client, UInt8[1])
    catch ex
        ex
    end
    closer = @async close(client)
    # the close waits for the writes issued before it, the parked one and the one behind
    sleep(0.2)
    @test !istaskdone(closer)
    @test isopen(client)

    # now the server reads everything, up to the close_notify
    outcome = boundedread(ssl, client) do
        n = 0
        try
            while !eof(ssl)
                n += length(readavailable(ssl))
            end
            (n, nothing)
        catch ex
            (n, ex)
        end
    end
    @test outcome !== :stalled
    # what the writers and the peer did, once the peer read it all (a stall aborted the
    # stream, which the writers would then report)
    if outcome !== :stalled
        @test boundedfetch(parked_writer, :stalled) === nothing
        # the waiting writer was issued before the close: its byte went out before the
        # close_notify, whichever of the two got the writer lock first
        @test boundedfetch(queued_writer, :stalled) == 1
        # the close returned, and did not throw
        @test boundedfetch(closer, :stalled) === nothing
        nread, err = outcome
        @test nread == written[] + 1
        # the close_notify, not a MAC failure
        @test err isa Base.IOError
        @test occursin("unexpected EOF", sprint(showerror, err))
    end
    close(ssl)
    # ended by the client's own close
    @test timedwait(() -> istaskdone(client_reader), 30.0) === :ok
    close(server)
end

@testset "AbortDuringGracefulClose" begin
    # `close(ssl, false)` has to take the transport down even when a graceful close is
    # already waiting for its turn behind a writer parked on a peer that is not reading.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)

    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, _ = park_writer(client, stop_writing)
    stop_writing[] = true
    queued_writer = @async write(client, UInt8[1])
    closer = @async close(client)
    # both wait behind the parked write: the writer for the writer lock, the close for
    # the writes issued before it to be through
    sleep(0.2)
    @test !istaskdone(closer)
    @test isopen(client)

    # the server never reads, so only the abort can end these. Its watch waits longer
    # here than the close is given below: the close has to stop waiting for the parked
    # write at once, on being told the stream is closed, not once some watch has failed
    # that write; the close's own ticks at `CLOSE_GRACE`
    grace = OpenSSL.ABORT_GRACE[]
    OpenSSL.ABORT_GRACE[] = 5.0
    prompt = try
        close(client, false)
        @test !isopen(client)
        timedwait(() -> istaskdone(closer), 2.0)
    finally
        OpenSSL.ABORT_GRACE[] = grace
    end
    @test OpenSSL.CLOSE_GRACE[] >= 5
    @test prompt === :ok
    @test timedwait(() -> istaskdone(parked_writer) && istaskdone(closer), 30.0) === :ok
    @test istaskdone(parked_writer) && fetch(parked_writer) isa Exception
    @test timedwait(() -> istaskdone(queued_writer), 30.0) === :ok
    @test istaskfailed(queued_writer)
    @test timedwait(() -> !isopen(client.io), 30.0) === :ok
    close(ssl)
    close(server)
end

@testset "GracefulCloseBehindParkedWriter" begin
    # `close(ssl)` waits for its close_notify's turn behind a writer parked on a peer
    # that is not reading; it must not wait for good. The watch fails the parked write
    # once nothing has moved for a period, and the close finishes as an abort.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, _ = park_writer(client, stop_writing)
    stop_writing[] = true
    # the close waits out `CLOSE_GRACE` of no progress; not the full ten seconds here.
    # Put back once the closer is through: it reads the grace when it gets to run
    grace = OpenSSL.CLOSE_GRACE[]
    OpenSSL.CLOSE_GRACE[] = 3.0
    closed = try
        closer = @async close(client)
        sleep(0.2)
        # while it waits the stream refuses new writes, at once rather than behind the
        # parked writer, and says why; it is still open
        @test !iswritable(client)
        @test isopen(client)
        refused = @elapsed err = try
            write(client, UInt8[1])
            nothing
        catch ex
            ex
        end
        @test err isa Base.IOError && occursin("being closed", sprint(showerror, err))
        @test refused < 1.0
        # and was never counted in: only the parked writer is in flight
        @test OpenSSL.writesinflight(client) == 1
        # a second close while the first waits returns at once
        second = @async close(client)
        @test timedwait(() -> istaskdone(second), 1.0) === :ok
        @test !istaskdone(closer)
        timedwait(() -> istaskdone(closer), 30.0)
    finally
        OpenSSL.CLOSE_GRACE[] = grace
    end
    @test closed === :ok
    @test timedwait(() -> istaskdone(parked_writer), 30.0) === :ok
    @test istaskdone(parked_writer) && fetch(parked_writer) isa Exception
    @test timedwait(() -> !isopen(client.io), 30.0) === :ok
    close(ssl)
    close(server)
end

@testset "CancelledInFlightWriter" begin
    # Linux only: these cancel a writer inside the socket write, and Base's write
    # completion callback (`uv_writecb_task`) schedules the waiting task unconditionally
    # while the request still names it, which it does until the task resumes. A write
    # that completes just as its task is cancelled therefore throws "schedule: Task not
    # runnable" out of the libuv callback, into whatever task runs the event loop, and
    # can wedge the loop. Windows and macOS grow the socket buffers for a peer that does
    # not read, so the parked record (not the whole write, see `park_writer`) completes
    # on its own there and hits that window, Windows often; on Linux it completes only
    # when the peer reads, which these tests' peers never do. Nothing this package can do
    # about it: the cancelled write's own cleanup here is sound, the moment of
    # cancellation is Base's
if !Sys.islinux()
    @test_skip Sys.islinux()
else
    # A writer cancelled inside the socket write itself, not while waiting for its turn:
    # libuv still holds the write, and a pointer into the chunk, so the socket has to be
    # closed outright, at once; a normal close would wait behind that very write.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, _ = park_writer(client, stop_writing)
    stop_writing[] = true
    schedule(parked_writer, InterruptException(); error=true)
    @test timedwait(() -> istaskdone(parked_writer), 5.0) === :ok
    @test istaskdone(parked_writer) && fetch(parked_writer) isa InterruptException
    @test !isopen(client)
    # the server never reads: only closing the handle outright can end this
    @test timedwait(() -> !isopen(client.io), 5.0) === :ok
    closer = @async close(client)
    @test timedwait(() -> istaskdone(closer), 5.0) === :ok
    close(ssl)

    # through the fallback, as without the internals `forceclose!` builds on: the
    # normal close it falls back to does not cancel the write, which libuv still holds
    # with a pointer into the chunk; the chunk stays referenced until that close is
    # through, here once the peer has read what was queued
    client, ssl = connected_pair(server_ctx, server)
    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, _ = park_writer(client, stop_writing)
    stop_writing[] = true
    # this write's chunk is told apart from anything else held (a chunk whose close
    # never got through stays held for good) by what was held before
    held(chunk) = Base.@lock(OpenSSL.KEPT_LOCK, chunk in OpenSSL.KEPT)
    OpenSSL.FORCECLOSE_FALLBACK[] = true
    try withkept(client) do kept
        schedule(parked_writer, InterruptException(); error=true)
        @test timedwait(() -> istaskdone(parked_writer), 5.0) === :ok
        # kept, however soon it was let go again (on the nightly `close` does not wait
        # behind the write)
        @test timedwait(() -> length(kept()) == 1, 5.0) === :ok
        # the peer reads, the queued write goes out, the close gets through; the read
        # started whatever was kept, so that the close is not left behind the write
        reader = @async try
            while !eof(ssl.io)
                readavailable(ssl.io)
            end
        catch
        end
        k = kept()
        @test length(k) == 1
        if length(k) == 1
            @test timedwait(() -> !held(only(k)), 30.0) === :ok
        end
        # the client's close got through, which the chunk let go says; the reader is
        # ended from this side, the peer's end not reaching it on every platform (macOS
        # may deliver neither a FIN nor a reset here)
        close(ssl.io)
        @test timedwait(() -> istaskdone(reader), 30.0) === :ok
    end
    finally
        # whatever failed above, the tests after this one close for real
        OpenSSL.FORCECLOSE_FALLBACK[] = false
    end
    close(ssl)

    # cancelled by any exception, not only an interrupt: the writer sees it, and the rest
    # happens all the same, the chunk kept, the cut recorded, the ticket through
    client, ssl = connected_pair(server_ctx, server)
    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, _ = park_writer(client, stop_writing)
    stop_writing[] = true
    cancel = ErrorException("cancelled")
    withkept(client) do kept
        schedule(parked_writer, cancel; error=true)
        @test timedwait(() -> istaskdone(parked_writer), 5.0) === :ok
        @test istaskdone(parked_writer) && fetch(parked_writer) === cancel
        @test timedwait(() -> length(kept()) == 1, 5.0) === :ok
    end
    data = client.data
    @test Base.@lock(data.cond, data.cut && OpenSSL.drained(data))
    @test timedwait(() -> !isopen(client.io), 5.0) === :ok
    close(client)
    close(ssl)
    close(server)
end
end

@testset "WriteCount" begin
    # the closing bit and the count of writes in flight share one word; the bit is the
    # sign bit, which exists whatever the width of `Int`
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    data = client.wstate
    counted = Ref(false)
    # counting in and out
    OpenSSL.countin!(client, counted)
    @test counted[] && OpenSSL.writesinflight(client) == 1
    OpenSSL.endwrite!(client)
    @test data[] == 0
    # once the close has set its bit, a write is refused without the word changing
    Threads.atomic_or!(data, OpenSSL.CLOSING)
    counted[] = false
    before = data[]
    OpenSSL.countin!(client, counted)
    @test !counted[] && data[] == before
    @test OpenSSL.closing(client)
    # and counting out what was never counted in is refused, not a borrow through the
    # bit; logged rather than thrown, being done in a `finally`
    @test_logs (:error, r"never counted in") OpenSSL.endwrite!(client)
    @test data[] == before
    data[] = 0
    close(client)
    close(ssl)
    close(server)
end

# a client stream connecting to `port` on a task, for a server that drives its side of
# the handshake itself
function connecting(port)
    @async begin
        client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
            Sockets.connect(ip"127.0.0.1", port))
        Sockets.connect(client; require_ssl_verification=false)
        client
    end
end

# the loop written to `accept`'s contract of old: one round per call, `OpenSSLError`
# when it needs more bytes, the wait for them and the deadline between calls. Returns
# the outcome and how many rounds asked for more
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
            # waits for bytes as such a loop does, with `eof(ssl.io)`, which is what
            # starts the socket reading; but not past the deadline, so on a task, which
            # a peer that stays silent leaves waiting until the socket closes
            arrival = @async eof(ssl.io)
            timedwait(() -> istaskdone(arrival), max(deadline - time(), 0.01))
        end
    end
end

@testset "LegacyAccept" begin
    # `accept` without `timeout` keeps the contract it had before 1.6.2: one round, which
    # does not wait for the peer, so the deadline a loop checks between calls holds
    # against a peer that stays silent; and the loop completes the handshake with one
    # that talks
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    silent = Sockets.connect(ip"127.0.0.1", port)
    ssl = OpenSSL.SSLStream(server_ctx, accept(server))
    outcome, rounds = acceptloop(ssl, time() + 0.5)
    @test outcome === :deadline_expired
    @test rounds >= 1
    # nothing failed: the loop could have gone on
    @test isopen(ssl)
    close(ssl)
    close(silent)

    client_task = connecting(port)
    ssl = OpenSSL.SSLStream(server_ctx, accept(server))
    outcome, rounds = acceptloop(ssl, time() + 30.0)
    @test outcome === :ok
    # the client's Finished is never in on the first round
    @test rounds >= 1
    connected = timedwait(() -> istaskdone(client_task), 30.0) === :ok
    @test connected
    if connected && outcome === :ok
        client = fetch(client_task)
        write(client, UInt8[1, 2, 3])
        @test read!(ssl, Vector{UInt8}(undef, 3)) == UInt8[1, 2, 3]
        write(ssl, UInt8[4])
        @test read!(client, Vector{UInt8}(undef, 1)) == UInt8[4]
        close(client)
    else
        # a client still in its handshake is released by the abort
        close(ssl, false)
    end
    close(ssl)
    close(server)
end

@testset "RawSSLCalls" begin
    # a call made on `ssl.ssl` from outside the package has what it produces written to
    # the socket by the write BIO callback itself, as before 1.6.2: an `SSL_accept` loop
    # of a caller's own (`ssl_accept`, under `ssl.lock`, as TLSStreams 0.2 runs it)
    # completes the handshake; and a raw write goes out behind the records the package's
    # own calls ticketed, so the peer reads them in order
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

    # the server reads nothing for now, so the client's writer parks; then a raw write on
    # the client waits, under `ssl.lock`, for the parked record to be through, and its
    # record goes out in the order OpenSSL made it in, whole. The parked write has
    # records still to make when the raw one is made, and the raw caller holds
    # `ssl.lock`, not the writers' lock: the raw record lands among that write's, which
    # the peer reads as what each is, nothing lost and no record out of sequence
    stop_writing = Threads.Atomic{Bool}(false)
    parked_writer, written = park_writer(client, stop_writing)
    stop_writing[] = true
    # the completed writes and the parked one, all zeros, and the marker
    nzeros = written[] + PARK_CHUNK
    marker = fill(UInt8(7), 100)
    # the turn is on the parked record for as long as it is pending
    turn0 = Base.@lock client.data.cond client.data.turn
    raw = @async Base.@lock client.lock begin
        n = Ref{Csize_t}(0)
        r = GC.@preserve marker ccall(
            (:SSL_write_ex, OpenSSL.libssl),
            Cint,
            (OpenSSL.SSL, Ptr{Cvoid}, Csize_t, Ptr{Csize_t}),
            client.ssl, pointer(marker), length(marker), n)
        (r, Int(n[]))
    end
    sleep(0.5)
    # the raw write waits while the parked record is pending. Windows grows the socket
    # buffers meanwhile and may let that record through, after which the raw write is
    # free to go: the turn tells which. Read in this order: a raw write that is done
    # had the turn move first, so a done write with the turn still on the record would
    # be the fault, and nothing else is
    rawdone = istaskdone(raw)
    stillparked = Base.@lock client.data.cond client.data.turn == turn0
    @test !(rawdone && stillparked)
    reader = @async read!(ssl, Vector{UInt8}(undef, nzeros + length(marker)))
    @test timedwait(() -> istaskdone(reader), 60.0) === :ok
    if istaskdone(reader)
        received = fetch(reader)
        @test count(==(0), received) == nzeros
        sevens = findall(==(7), received)
        @test length(sevens) == length(marker)
        # in one piece
        @test !isempty(sevens) && sevens == sevens[1]:sevens[1] + length(marker) - 1
    end
    @test timedwait(() -> istaskdone(raw) && istaskdone(parked_writer), 30.0) === :ok
    @test istaskdone(raw) && fetch(raw) == (1, 100)
    @test istaskdone(parked_writer) && fetch(parked_writer) === nothing
    close(client)
    close(ssl)
    close(server)
end

@testset "RawWriteGivesUp" begin
    # a raw write waits for the records ticketed before it. One whose ticket no task will
    # ever drain would hold it for good, under `ssl.lock`, where no close or watch can
    # reach it: once nothing has moved for CLOSE_GRACE the wait gives up, the call fails,
    # the loss is recorded so nothing more goes out, and the socket is not cut, no write
    # having been started
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    data = client.data
    # a ticket taken and never drained
    stale = Base.@lock client.lock begin
        append!(data.buf, UInt8[0x17, 0x03, 0x03, 0x00, 0x01, 0x00])
        take!(data)
    end
    grace = OpenSSL.CLOSE_GRACE[]
    OpenSSL.CLOSE_GRACE[] = 1.0
    try
        marker = fill(UInt8(7), 10)
        raw = @async Base.@lock client.lock begin
            n = Ref{Csize_t}(0)
            GC.@preserve marker ccall(
                (:SSL_write_ex, OpenSSL.libssl),
                Cint,
                (OpenSSL.SSL, Ptr{Cvoid}, Csize_t, Ptr{Csize_t}),
                client.ssl, pointer(marker), length(marker), n)
        end
        @test timedwait(() -> istaskdone(raw), 10.0) === :ok
        @test istaskdone(raw) && fetch(raw) != 1
        @test data.lostfrom == stale.ticket + 1
        @test Base.@lock(data.cond, !data.cut)
        # the stream is unusable from here
        @test_throws Base.IOError write(client, UInt8[1])
        @test !isopen(client)
    finally
        OpenSSL.CLOSE_GRACE[] = grace
    end
    close(client, false)
    close(ssl)
    close(server)
end

@testset "DetachedDrainNotScheduled" begin
    # what a read produces for the peer goes out from a task of its own (see
    # `finish_sslcall!`). When that task cannot be made or scheduled, the record's ticket
    # is given up and the stream aborted, so that the writers after it fail rather than
    # wait for its turn for good. Driven directly: on current OpenSSL the one such reply,
    # to a KeyUpdate, goes out with the next write instead, so no traffic reaches this
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    data = client.data
    # a record a read left in the write BIO, and its ticket, as `@sslcall` takes them;
    # never sent, so its bytes do not matter
    pending = Base.@lock client.lock begin
        append!(data.buf, UInt8[0x17, 0x03, 0x03, 0x00, 0x01, 0x00])
        take!(data)
    end
    @test pending isa OpenSSL.PendingWrite
    # only the reply's task fails to be made: the closure `finish_sslcall!` hands
    # `background` is told by what it captures, `pending`; the watches and cleanups go on
    OpenSSL.ONBACKGROUND[] = f -> hasproperty(f, :pending) && throw(OutOfMemoryError())
    try
        err = try
            OpenSSL.finish_sslcall!(client, OpenSSL.SSL_ERROR_NONE, pending, nothing; detach=true)
            nothing
        catch ex
            ex
        end
        @test err isa OutOfMemoryError
        @test !isopen(client)
        # the ticket was consumed, and nothing after it may be sent
        @test Base.@lock(data.cond, OpenSSL.drained(data))
        @test data.lostfrom == pending.ticket
        # a write after it fails at once, not parked on the ticket that was given up
        writer = @async try
            write(client, UInt8[2])
        catch ex
            ex
        end
        @test timedwait(() -> istaskdone(writer), 10.0) === :ok
        @test istaskdone(writer) && fetch(writer) isa Base.IOError
        @test timedwait(() -> !isopen(client.io), 30.0) === :ok
    finally
        OpenSSL.ONBACKGROUND[] = nothing
    end
    close(client, false)
    close(ssl)
    close(server)
end

@testset "SpareBuffer" begin
    # a chunk that reached the socket becomes the write BIO's next buffer; the peer
    # still reads every write whole and in order, across sizes around a record's and a
    # write of many records
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    payloads = [rand(UInt8, n) for n in (1, 100, 16383, 16384, 16385, 50_000, 2^20 + 7, 3)]
    expected = reduce(vcat, payloads)
    reader = @async read!(ssl, Vector{UInt8}(undef, length(expected)))
    for payload in payloads
        write(client, payload)
    end
    @test awaitread(reader, ssl, client) == expected
    # the last write's chunk is kept, emptied, for the next call
    spare = client.data.spare
    @test spare isa Vector{UInt8} && isempty(spare)
    close(client)
    close(ssl)
    close(server)
end

@testset "Ticker" begin
    # a one-shot timer calls back once; closed before it goes off, not at all; and
    # neither logs an error (reading the timer on its end once did, on Julia 1.7)
    calls = Threads.Atomic{Int}(0)
    @test_logs min_level=Base.CoreLogging.Warn begin
        t = OpenSSL.ticker(_ -> Threads.atomic_add!(calls, 1), 0.1)
        sleep(0.5)
        @test calls[] == 1
        @test !isopen(t)
        t = OpenSSL.ticker(_ -> Threads.atomic_add!(calls, 1), 5.0)
        close(t)
        sleep(0.3)
        @test calls[] == 1
    end
    # an interrupt in a callback does not end the timer: it is warned about, and the
    # next tick comes
    calls[] = 0
    t = @test_logs (:warn, r"interrupt") match_mode=:any begin
        t = OpenSSL.ticker(0.05; interval=0.05) do _
            Threads.atomic_add!(calls, 1) == 0 && throw(InterruptException())
        end
        sleep(0.5)
        t
    end
    @test calls[] >= 3
    close(t)
    # a repeating timer's tick cut short is dropped, not run again at once: a watch run
    # again at once would judge nothing to have moved in no time
    times = Float64[]
    timeslock = ReentrantLock()
    started = time()
    t = @test_logs (:warn, r"interrupt") match_mode=:any begin
        t = OpenSSL.ticker(0.2; interval=0.2) do _
            first = Base.@lock timeslock (push!(times, time()); length(times) == 1)
            first && throw(InterruptException())
        end
        sleep(0.7)
        t
    end
    close(t)
    # against the timer's own schedule, not the first call, which may run late: the
    # second call comes at the second tick at the earliest, not at once after the first
    second = Base.@lock timeslock (length(times) >= 2 ? times[2] : 0.0)
    @test second >= started + 0.35
    # a one-shot timer's callback interrupted before it got to its end runs again: the
    # tick stays due until it has run to its end once
    calls[] = 0
    @test_logs (:warn, r"interrupt") match_mode=:any begin
        OpenSSL.ticker(0.05) do _
            Threads.atomic_add!(calls, 1) == 0 && throw(InterruptException())
        end
        sleep(0.5)
    end
    @test calls[] == 2
    # an error in a callback is logged and ends the timer, closed
    calls[] = 0
    t = @test_logs (:error, r"timer callback failed") match_mode=:any begin
        t = OpenSSL.ticker(0.05; interval=0.05) do _
            Threads.atomic_add!(calls, 1)
            error("from the callback")
        end
        sleep(0.5)
        t
    end
    @test calls[] == 1
    @test !isopen(t)
    # a repeating one calls back on each tick, and not once more after its owner closed
    # it, whatever tick raced the close
    calls[] = 0
    t = OpenSSL.ticker(_ -> Threads.atomic_add!(calls, 1), 0.05; interval=0.05)
    sleep(0.5)
    @test calls[] >= 3
    close(t)
    # a callback that passed the open check just before the close, on another thread,
    # may still be under way: wait until the count has stopped changing
    settled = timedwait(10.0; pollint=0.1) do
        c = calls[]
        sleep(0.1)
        calls[] == c
    end
    @test settled === :ok
    after = calls[]
    sleep(0.3)
    @test calls[] == after
end

@testset "CallerNotPinned" begin
    # the tasks the library starts do not pin the task that starts them to its thread,
    # as `@async` does from Julia 1.7: an abort from a spawned task leaves it free
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    # an abort, a graceful close, and a handshake with a deadline, each from a spawned
    # task: the last two make timers, which `Timer(cb, ...)` would pin up to Julia 1.11
    client, ssl = connected_pair(server_ctx, server)
    @test fetch(Threads.@spawn (close(client, false); current_task().sticky)) == false
    close(ssl)
    client, ssl = connected_pair(server_ctx, server)
    @test fetch(Threads.@spawn (close(client); current_task().sticky)) == false
    close(ssl)
    port = Sockets.getsockname(server)[2]
    server_task = @async begin
        s = OpenSSL.SSLStream(server_ctx, accept(server))
        Sockets.accept(s; timeout=30)
        s
    end
    try
        pinned = fetch(Threads.@spawn begin
            c = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
                Sockets.connect(ip"127.0.0.1", port))
            Sockets.connect(c; require_ssl_verification=false, timeout=30)
            close(c)
            current_task().sticky
        end)
        @test pinned == false
    finally
        # should the handshake fail, leave neither the server task nor the listener
        close(server)
        # the server's side of the handshake may still be finishing: give it the time
        # well past the server side's own deadline
        @test timedwait(() -> istaskdone(server_task), 60.0) === :ok
        istaskdone(server_task) && !istaskfailed(server_task) && close(fetch(server_task))
    end
end

@testset "WatchEndsStandingCount" begin
    # a write counted in that never counts out (an interrupt at the wrong moment, say)
    # must not keep a graceful close waiting for good: nothing moves, and the close's
    # watch gives up and ends it, whether the socket is still open or already closed
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    grace = OpenSSL.CLOSE_GRACE[]
    OpenSSL.CLOSE_GRACE[] = 0.5
    try
        for socket_closed_first in (false, true)
            client, ssl = connected_pair(server_ctx, server)
            Threads.atomic_add!(client.wstate, 1)
            socket_closed_first && close(client.io)
            try
                closer = @async close(client)
                @test timedwait(() -> istaskdone(closer), 10.0) === :ok
                @test !isopen(client)
            finally
                # should the close hang, leave nothing behind for the testsets after
                close(client, false)
                close(ssl)
            end
        end
    finally
        OpenSSL.CLOSE_GRACE[] = grace
    end
    close(server)
end

@testset "CloseStopsLoopingWriter" begin
    # a writer calling `write` back to back must not keep a graceful close waiting: the
    # writer lock does not hand itself over in order, so the close would lose to each
    # next write. Writes that start after the close fail, and the close gets through.
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    reader = @async try
        while !eof(ssl)
            readavailable(ssl)
        end
        :eof
    catch ex
        ex
    end
    # the client reads too, which takes the server's session tickets off its socket:
    # closed with them unread, the kernel would reset the connection rather than end it,
    # and the peer might lose the close_notify to the reset
    client_reader = @async try
        while !eof(client)
            readavailable(client)
        end
    catch
    end
    # it retries after being refused, too, on another thread when there is one: a
    # refused write must not count, or a retrying writer could keep the close waiting
    # until its watch gave up
    writer = Threads.@spawn begin
        chunk = zeros(UInt8, 16 * 1024)
        refusals = 0
        while isopen(client)
            try
                write(client, chunk)
            catch ex
                ex isa Base.IOError || rethrow()
                refusals += 1
                # a refusal comes back without waiting on anything: on one thread, a
                # loop that never yields would keep everything else from running
                yield()
            end
        end
        refusals
    end
    sleep(0.5)
    @test !istaskdone(writer)
    closer = @async close(client)
    # well before the close's watch could give up, at `CLOSE_GRACE`
    @test OpenSSL.CLOSE_GRACE[] >= 5
    @test timedwait(() -> istaskdone(closer), 3.0) === :ok
    @test timedwait(() -> istaskdone(writer), 10.0) === :ok
    # how many refusals it met depends on the timing; that it stopped is what counts
    @test istaskdone(writer) && fetch(writer) isa Int
    @test OpenSSL.writesinflight(client) == 0
    awaitpeer(reader, ssl, client) do ended
        # the close was graceful: the peer got the close_notify, not a cut connection
        @test ended isa Base.IOError && occursin("unexpected EOF", sprint(showerror, ended))
    end
    # and an empty write on a closed stream is no error, as it never was; a write that is
    # not empty says the stream is closed, no longer that it is being closed
    @test write(client, UInt8[]) == 0
    late = try
        write(client, UInt8[1])
        nothing
    catch ex
        ex
    end
    @test late isa Base.IOError && occursin("requires ssl to be open", sprint(showerror, late))
    close(server)
end

@testset "FinishUnderDeadline" begin
    # the handshake's last step (the certificate check, for `connect`) counts toward
    # its deadline: one that runs past it ends in the timeout, the stream closed
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    # one handshake! call site and one kind of last step for both runs below, so that the
    # first compiles what the second needs, which then has only its own rounds to fit
    # in its deadline
    # (@eval'd into the package for `@geterror` and the internals it names)
    deadline_connect! = @eval OpenSSL (client, timeout, finish) ->
        handshake!(client, :connect, timeout; finish=finish) do
            @geterror client :connect ssl_connect(client.ssl)
        end
    # notes that the stream was open when the step began, the rounds before it having
    # finished inside the deadline; then, if told to, waits for the deadline to close it
    laststep(client, entered, wait) = function ()
        entered[] = isopen(client)
        wait && timedwait(() -> !isopen(client), 30.0)
        nothing
    end
    function attempt(timeout, wait)
        # this attempt's own, not the testset's of the same names
        local server_task, client, entered, err
        server_task = @async begin
            s = OpenSSL.SSLStream(server_ctx, accept(server))
            try
                Sockets.accept(s; timeout=30)
            catch
            end
            s
        end
        client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
            Sockets.connect(ip"127.0.0.1", port))
        entered = Ref(false)
        err = try
            Base.invokelatest(deadline_connect!, client, timeout,
                laststep(client, entered, wait))
            nothing
        catch ex
            ex
        end
        @test timedwait(() -> istaskdone(server_task), 30.0) === :ok
        istaskdone(server_task) && close(fetch(server_task))
        return client, entered[], err
    end
    # the warm-up, well inside its deadline
    client, entered, err = attempt(60.0, false)
    @test entered
    @test err === nothing
    @test isopen(client)
    close(client)
    client, entered, err = attempt(3.0, true)
    @test entered
    @test err isa Base.IOError && occursin("timed out", sprint(showerror, err))
    @test !isopen(client)
    close(server)
end

@testset "WatchStandsDown" begin
    # a watch that ticks after its graceful close handed the socket to its normal close
    # stands down: it neither aborts the stream nor cuts its socket, whatever it sees;
    # and one that sees nothing moved on a stream not handed off gives up
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    for handedoff in (true, false)
        client, ssl = connected_pair(server_ctx, server)
        watch = OpenSSL.AbortWatch(client)
        Base.@lock client.lock (client.data.handedoff = handedoff)
        timer = Timer(3600)
        try
            watch(timer)
            @test client.data.aborted == !handedoff
            if handedoff
                @test isopen(client.io)
            else
                # closed outright: up to Julia 1.8 a socket reads as open until its close
                # callback has run
                @test timedwait(() -> !isopen(client.io), 5.0) === :ok
            end
            @test !isopen(timer)
        finally
            close(timer)
            close(client, false)
            close(ssl)
        end
    end
    close(server)
end

@testset "FailedWriteKeepsNothing" begin
    # a write that ended with the socket's own error: libuv is done with it and holds
    # no pointer into its chunk, which is not kept. A reset from the peer gives one, on
    # Linux for sure: a peer closing with bytes unread resets the connection
    if Sys.islinux()
        server_ctx = selfsigned_server_ctx()
        port, server = Sockets.listenany(ip"127.0.0.1", 20000)
        client, ssl = connected_pair(server_ctx, server)
        stop_writing = Threads.Atomic{Bool}(false)
        parked_writer, _ = park_writer(client, stop_writing)
        stop_writing[] = true
        try
            withkept(client) do kept
                close(ssl.io)
                @test timedwait(() -> istaskdone(parked_writer), 10.0) === :ok
                failure = istaskdone(parked_writer) ? fetch(parked_writer) : nothing
                @test failure isa Base.IOError
                @test isempty(kept())
            end
        finally
            close(client, false)
            close(ssl)
            close(server)
        end
    end
end

@testset "UndrainedTicket" begin
    # a ticket taken and never drained (its task stopped in between) must not hold the
    # tickets behind it for good: once the stream is aborted and its watch gives up,
    # the socket goes, and a writer waiting for its turn behind that ticket fails
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    data = client.data
    # the orphan, taken under `ssl.lock`, as `take!` hands tickets out
    Base.@lock client.lock (data.nextticket += 1)
    writer = @async try
        write(client, UInt8[1])
        nothing
    catch ex
        ex
    end
    queued() = Base.@lock data.cond data.waiting
    @test timedwait(() -> queued() == 1, 5.0) === :ok
    grace = OpenSSL.ABORT_GRACE[]
    OpenSSL.ABORT_GRACE[] = 0.5
    try
        close(client, false)
        @test timedwait(() -> istaskdone(writer), 10.0) === :ok
        @test istaskdone(writer) && fetch(writer) isa Base.IOError
        @test timedwait(() -> !isopen(client.io), 10.0) === :ok
    finally
        OpenSSL.ABORT_GRACE[] = grace
    end
    close(ssl)

    # the same with the handle closed through the fallback, as without the internals
    # `forceclose!` builds on: the socket's status then says closed only later, and the
    # waits must end on what the cut recorded, not on that
    client, ssl = connected_pair(server_ctx, server)
    data = client.data
    # under `ssl.lock`, as `take!` hands tickets out
    Base.@lock client.lock (data.nextticket += 1)
    writer = @async try
        write(client, UInt8[1])
        nothing
    catch ex
        ex
    end
    @test timedwait(() -> queued() == 1, 5.0) === :ok
    OpenSSL.ABORT_GRACE[] = 0.5
    OpenSSL.FORCECLOSE_FALLBACK[] = true
    try
        close(client, false)
        @test timedwait(() -> istaskdone(writer), 10.0) === :ok
        @test istaskdone(writer) && fetch(writer) isa Base.IOError
        @test timedwait(() -> !isopen(client.io), 10.0) === :ok
    finally
        OpenSSL.FORCECLOSE_FALLBACK[] = false
        OpenSSL.ABORT_GRACE[] = grace
    end
    close(ssl)
    close(server)
end

@testset "FailedCallAbortsAtOnce" begin
    # a call that fails closes and aborts the stream in one go, under `ssl.lock`: by
    # the time `@sslcall` hands back, the abort has been started, so nothing landing
    # in between (another task's abort, an interrupt) can leave the stream closed with
    # no abort run, or its alert behind. `@sslcall` is run by hand to look right there.
    # With `data.cond` held by another task too: the claim takes no lock but `ssl.lock`,
    # so the alert-less abort after it cannot claim the stream first
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    # each run its own set, so that a failure says which
    @testset "contended=$contended" for contended in (false, true)
        client, ssl = connected_pair(server_ctx, server)
        data = client.data
        # a record that does not decrypt: the peek fails, OpenSSL queues a bad_record_mac
        write(ssl.io, UInt8[0x17, 0x03, 0x03, 0x00, 0x11, fill(0xaa, 17)...])
        # held by a task of its own, the lock being reentrant: the claim must not depend
        # on it
        held, release = Base.Event(), Base.Event()
        holder = contended ? (@async Base.@lock data.cond (notify(held); wait(release))) : nothing
        contended && wait(held)
        # in a task of its own, under a deadline: a claim that took `data.cond` would stay
        # parked behind the holder, which is a failure to report, not a hang
        run = @async try
            # a `let`: `@eval` runs at the module's top level, and would leave a global
            # behind
            @eval OpenSSL let client = $client, contended = $contended
                local ret, pending, err
                # a message another call left for this task: not the failed call's to
                # take, nor to show
                task_local_storage(:openssl_err, "stale")
                for round in 1:100
                    eof(client.io) && error("the socket ended before the record failed")
                    ret, pending, err = @sslcall client :peek ccall((:SSL_peek_ex, libssl), Cint,
                        (SSL, Ptr{UInt8}, Csize_t, Ptr{Csize_t}), client.ssl, client.peekbuf, 1, client.peekbytes)
                    err === nothing || break
                    # its drain would wait for `data.cond`, held until this is done
                    contended && pending !== nothing &&
                        error("a round before the failing one produced output")
                    finish_sslcall!(client, ret, pending, err)
                    round == 100 && error("the record did not fail")
                end
                aborted = getfield(client, :data).aborted
                # another abort now does nothing more
                close(client, false)
                res = try
                    finish_sslcall!(client, ret, pending, err)
                    :no_error
                catch ex
                    ex
                end
                (aborted, res, get(task_local_storage(), :openssl_err, nothing))
            end
        catch ex
            ex
        end
        out = boundedfetch(run, :stalled)
        if contended
            notify(release)
            wait(holder)
        end
        @test out !== :stalled
        if out === :stalled
            # the run, released, is let finish should it have waited behind the holder;
            # else its socket is cut, which wakes it wherever it waits (it can hold
            # `client.lock`, which an abort would wait for, so it is not aborted)
            contended && timedwait(() -> istaskdone(run), 10.0)
            istaskdone(run) || OpenSSL.cut!(data)
        end
        @test out isa Tuple
        aborted, res, left = out isa Tuple ? out : (false, :not_run, nothing)
        @test aborted
        @test res isa Base.IOError
        # the reason reaches the message, and leaves the thread's error queue: nothing
        # for a later call to take for its own
        @test res isa Base.IOError && occursin("bad record mac", lowercase(res.msg))
        @test ccall((:ERR_peek_error, OpenSSL.libcrypto), Culong, ()) == 0
        @test res isa Base.IOError && !occursin("stale", res.msg)
        @test left == "stale"
        @test timedwait(() -> Base.@lock(data.cond, OpenSSL.drained(data)), 10.0) === :ok
        # and the peer got the alert, not a bare end of the connection; only asked once
        # the abort ran, the peer having nothing to read otherwise
        if aborted
            alerted = boundedread(ssl, client) do
                try
                    eof(ssl)
                    false
                catch ex
                    ex isa Base.IOError && !occursin("unexpected EOF", sprint(showerror, ex))
                end
            end
            @test alerted === true
        end
        close(ssl)
    end
    close(server)
end

@testset "AcceptTimeout" begin
    # a client that connects and then says nothing
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    server_task = @async begin
        ssl = OpenSSL.SSLStream(server_ctx, accept(server))
        try
            Sockets.accept(ssl; timeout=0.5)
            nothing
        catch ex
            # the timeout closes the stream
            (ex, isopen(ssl))
        finally
            close(ssl)
        end
    end
    silent = Sockets.connect(ip"127.0.0.1", port)
    # fetched only once done, a stalled handshake failing the test rather than hanging
    # it; and a handshake that completed (`nothing`) failing it too, not erroring
    r = boundedfetch(server_task, :stalled; timeout=10.0)
    @test r !== :stalled
    err, open = r isa Tuple ? r : (r, true)
    @test err isa Base.IOError
    @test occursin("timed out", sprint(showerror, err))
    @test !open
    close(silent)

    # a client that goes away mid-handshake: the same EOFError as without a timeout,
    # not wrapped in the error of the task that waited on the socket
    server_task = @async begin
        ssl = OpenSSL.SSLStream(server_ctx, accept(server))
        try
            Sockets.accept(ssl; timeout=10)
            nothing
        catch ex
            # the peer going away closes the stream too
            (ex, isopen(ssl))
        finally
            close(ssl)
        end
    end
    leaver = Sockets.connect(ip"127.0.0.1", port)
    sleep(0.2)
    close(leaver)
    r = boundedfetch(server_task, :stalled; timeout=10.0)
    @test r !== :stalled
    err, open = r isa Tuple ? r : (r, true)
    @test err isa EOFError
    @test !open
    # a timeout that is not a positive number is refused before anything happens
    probe = OpenSSL.SSLStream(server_ctx, Sockets.connect(ip"127.0.0.1", port))
    @test_throws ArgumentError Sockets.accept(probe; timeout=NaN)
    @test_throws ArgumentError Sockets.accept(probe; timeout=0)
    @test_throws ArgumentError Sockets.accept(probe; timeout=-1)
    @test isopen(probe)
    close(probe)
    # the probe's connection is still in the listen backlog: take it out of the way
    close(accept(server))

    # the client side has the same deadline: a server that accepts and then says nothing
    mute = @async accept(server)
    client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
        Sockets.connect(ip"127.0.0.1", port))
    err = try
        Sockets.connect(client; require_ssl_verification=false, timeout=0.5)
        nothing
    catch ex
        ex
    end
    @test err isa Base.IOError
    @test occursin("timed out", sprint(showerror, err))
    @test !isopen(client)
    close(fetch(mute))
    close(server)
end

@testset "InterruptedHandshakeCleanup" begin
    # an exception thrown into a task whose failed handshake is waiting to abort the
    # stream, an interrupt or any other: it goes on at once, and the abort is done all the
    # same, on a task of the library's, with nothing logged as a failure
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    for injected in (InterruptException(), ErrorException("cancelled"))
        peer_task = @async accept(server)
        client = OpenSSL.SSLStream(OpenSSL.SSLContext(OpenSSL.TLSClientMethod(), ""),
            Sockets.connect(ip"127.0.0.1", port))
        peer = fetch(peer_task)
        # the task's logger, and its tasks', collects what the library logs
        logger = Test.TestLogger(; min_level=Base.CoreLogging.Warn)
        handshaker = Base.CoreLogging.with_logger(logger) do
            @async try
                Sockets.connect(client; require_ssl_verification=false)
                nothing
            catch ex
                ex
            end
        end
        # the ClientHello is out: the handshake waits for the reply
        @test !eof(peer)
        lock(client.lock)
        try
            # the peer goes, the handshake fails, and its abort waits for the lock
            close(peer)
            sleep(1.0)
            @test !istaskdone(handshaker)
            schedule(handshaker, injected; error=true)
            sleep(0.5)
        finally
            unlock(client.lock)
        end
        @test timedwait(() -> istaskdone(handshaker), 10.0) === :ok
        @test istaskdone(handshaker) && fetch(handshaker) === injected
        # on the task the abort was left to, should it have been
        @test timedwait(() -> !isopen(client), 10.0) === :ok
        @test timedwait(() -> !isopen(client.io), 10.0) === :ok
        @test isempty(logger.logs)
    end
    close(server)
end

@testset "SurelyLocked" begin
    # a cleanup section's lock, taken surely: an exception thrown into the task while it
    # waits for it goes on at once, and the section, and what is to follow it, are left
    # to a task of the library's, which runs them once the lock is free
    for l in (ReentrantLock(), Threads.Condition()), then in (false, true)
        ran = Threads.Atomic{Int}(0)
        injected = ErrorException("cancelled")
        lock(l)
        t = @async try
            if then
                OpenSSL.surely(() -> (ran[] = 1), l; then=r -> (ran[] = r + 1))
            else
                OpenSSL.surely(() -> (ran[] = 1), l)
            end
            nothing
        catch ex
            ex
        end
        try
            sleep(0.5)
            @test !istaskdone(t)
            schedule(t, injected; error=true)
            @test timedwait(() -> istaskdone(t), 10.0) === :ok
            @test istaskdone(t) && fetch(t) === injected
            # not while the lock is held
            sleep(0.2)
            @test ran[] == 0
        finally
            unlock(l)
        end
        @test timedwait(() -> ran[] == (then ? 2 : 1), 10.0) === :ok
        @test timedwait(() -> !islocked(l), 10.0) === :ok
        # nothing thrown in: on the caller's task, `then` on the section's value
        @test OpenSSL.surely(() -> 42, l) == 42
        @test OpenSSL.surely(() -> 42, l; then=r -> r + 1) == 43
    end
    # what is left to a task of the library's and fails is logged, not lost
    logger = Test.TestLogger(; min_level=Base.CoreLogging.Error)
    t = Base.CoreLogging.with_logger(() -> OpenSSL.leave(() -> error("left and failed")), logger)
    @test timedwait(() -> istaskdone(t), 10.0) === :ok
    @test any(r -> occursin("left to a task of the library failed", r.message), logger.logs)
    # as is an interrupt that what was left throws itself, once, rather than taken for one
    # that landed before the hold and run again
    runs = Threads.Atomic{Int}(0)
    logger = Test.TestLogger(; min_level=Base.CoreLogging.Error)
    t = Base.CoreLogging.with_logger(logger) do
        OpenSSL.leave(() -> (Threads.atomic_add!(runs, 1); throw(InterruptException())))
    end
    @test timedwait(() -> istaskdone(t), 10.0) === :ok
    @test runs[] == 1
    @test any(r -> occursin("left to a task of the library was interrupted", r.message), logger.logs)
end

@testset "InterruptedTake" begin
    # taking a call's records waits for nothing: a writer takes its ticket while another
    # task holds `data.cond`, so nothing thrown into it can land between making records
    # and ticketing them. Stopped then, waiting for `data.cond` in `drain!`, its records
    # are lost, and the stream with them; none of them reaches the peer
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    data = client.data
    injected = ErrorException("cancelled")
    before = data.nextticket
    lock(data.cond)
    writer = @async try
        write(client, b"first")
        nothing
    catch ex
        ex
    end
    try
        # ticketed with `data.cond` held here: `take!` did not wait for it
        @test timedwait(() -> data.nextticket == before + 1, 10.0) === :ok
        sleep(0.2)
        @test !istaskdone(writer)
        schedule(writer, injected; error=true)
        sleep(0.2)
    finally
        unlock(data.cond)
    end
    @test timedwait(() -> istaskdone(writer), 10.0) === :ok
    @test istaskdone(writer) && fetch(writer) === injected
    @test timedwait(() -> !isopen(client), 10.0) === :ok
    @test_throws Base.IOError write(client, b"second")
    reader = @async try
        got = UInt8[]
        while !eof(ssl)
            append!(got, readavailable(ssl))
        end
        String(got)
    catch ex
        ex
    end
    awaitpeer(reader, ssl, client) do r
        # nothing, or the socket going (a reset, the client not having read what the
        # server sent after the handshake); not a record, nor an SSL error about one
        @test r == "" || (r isa Base.IOError && !occursin("SSL", r.msg))
    end
    close(server)
end

# a logger that throws on every message, as one that does not catch its own errors
# passes them on; noting the messages it was given
struct ThrowingLogger <: Base.CoreLogging.AbstractLogger
    seen::Vector{String}
    lock::ReentrantLock
end
ThrowingLogger() = ThrowingLogger(String[], ReentrantLock())
Base.CoreLogging.min_enabled_level(::ThrowingLogger) = Base.CoreLogging.Debug
Base.CoreLogging.shouldlog(::ThrowingLogger, args...) = true
Base.CoreLogging.catch_exceptions(::ThrowingLogger) = false
function Base.CoreLogging.handle_message(logger::ThrowingLogger, level, message, args...; kwargs...)
    Base.@lock logger.lock push!(logger.seen, string(message))
    error("the logger threw")
end
saw(logger::ThrowingLogger, what) = Base.@lock logger.lock any(m -> occursin(what, m), logger.seen)

@testset "ThrowingLogger" begin
    # Linux only: see CancelledInFlightWriter
if !Sys.islinux()
    @test_skip Sys.islinux()
else
    # what the library logs on its cleanup paths cannot stop them: a cancelled in-flight
    # write through the fallback close, which logs before it schedules the close, with
    # the writer (and the tasks it starts) logging to a logger that throws
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    client, ssl = connected_pair(server_ctx, server)
    stop_writing = Threads.Atomic{Bool}(false)
    logger = ThrowingLogger()
    parked_writer, _ = Base.CoreLogging.with_logger(logger) do
        park_writer(client, stop_writing)
    end
    stop_writing[] = true
    OpenSSL.FORCECLOSE_FALLBACK[] = true
    try withkept(client) do kept
        schedule(parked_writer, InterruptException(); error=true)
        @test timedwait(() -> istaskdone(parked_writer), 5.0) === :ok
        @test istaskdone(parked_writer) && fetch(parked_writer) isa InterruptException
        # the fallback's log reached, and the fallback on past it: the chunk kept until
        # the close is through
        @test saw(logger, "could not close the socket handle outright")
        @test timedwait(() -> length(kept()) == 1, 5.0) === :ok
        data = client.data
        @test Base.@lock(data.cond, data.cut)
        # the peer reads, the queued write goes out, the close the fallback scheduled
        # gets through
        reader = @async try
            while !eof(ssl.io)
                readavailable(ssl.io)
            end
        catch
        end
        @test timedwait(() -> !isopen(client.io), 30.0) === :ok
        # the reader ended from this side, the peer's end not reaching it on every
        # platform (macOS may deliver neither a FIN nor a reset here)
        close(ssl.io)
        @test timedwait(() -> istaskdone(reader), 30.0) === :ok
    end
    finally
        OpenSSL.FORCECLOSE_FALLBACK[] = false
    end
    close(ssl)

    # a graceful close whose close_notify cannot go out, the socket gone under it: the
    # close logs that, on the caller's task, and returns all the same
    client, ssl = connected_pair(server_ctx, server)
    close(client.io)
    logger = ThrowingLogger()
    Base.CoreLogging.with_logger(logger) do
        @test (close(client); true)
    end
    # the log was reached, and threw
    @test saw(logger, "close_notify not sent")
    @test !isopen(client)
    close(ssl)
    close(server)
end
end

@testset "LostRecordNoCloseNotify" begin
    server_ctx = selfsigned_server_ctx()
    port, server = Sockets.listenany(ip"127.0.0.1", 20000)
    # a graceful close on a stream that lost a record produces no close_notify: it would
    # be refused, and would mark the session as shut down cleanly
    client, ssl = connected_pair(server_ctx, server)
    data = client.data
    Base.@lock data.cond (data.lostfrom = data.nextticket)
    @test Base.@lock(client.lock, OpenSSL.closelocked!(client)) === nothing
    close(client, false)
    close(ssl)
    # and through the public close: the stream closed, and the peer gets no close_notify
    # (which the ticket order would refuse anyway: that none is produced, keeping the
    # session from being marked as shut down cleanly, is the case above's to pin)
    client, ssl = connected_pair(server_ctx, server)
    data = client.data
    Base.@lock data.cond (data.lostfrom = data.nextticket)
    close(client)
    @test !isopen(client)
    # nothing clean-looking reaches the peer: a bare end, or a reset (the client not
    # having read what the server sent after the handshake), not the "unexpected EOF" a
    # close_notify would show as
    # read from a task of its own, under a deadline: a socket left open would otherwise
    # hang the suite rather than fail this
    reader = @async try
        eof(ssl)
    catch ex
        ex
    end
    awaitpeer(reader, ssl, client) do r
        @test r === true || (r isa Base.IOError && !occursin("unexpected EOF", r.msg))
    end
    close(server)
end
