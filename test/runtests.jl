using Dates
using MozillaCACerts_jll
using OpenSSL
using OpenSSL_jll
using Sockets
using Test

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

    cert = certs_pem[2]

    x509_cert = X509Certificate(cert)
    @test String(x509_cert.subject_name) == "/C=BE/O=GlobalSign nv-sa/OU=Root CA/CN=GlobalSign Root CA"
    @test String(x509_cert.issuer_name) == "/C=BE/O=GlobalSign nv-sa/OU=Root CA/CN=GlobalSign Root CA"
    @test String(x509_cert.time_not_before) == "Sep  1 12:00:00 1998 GMT"
    @test String(x509_cert.time_not_after) == "Jan 28 12:00:00 2028 GMT"

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

    @test String(x509_server_cert.issuer_name) == "/C=US/O=Let's Encrypt/CN=R3"
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
    if OpenSSL.version_number() ≥ v"3"
        OpenSSL.load_legacy_provider()
    end
    evp_ciphers = [
        EvpEncNull(),
        EvpBlowFishCBC(), # legacy
        EvpBlowFishECB(), # legacy
        #EvpBlowFishCFB(), // not supported
        EvpBlowFishOFB(), # legacy
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

@testset "EncryptCustomKey" begin
    # EvpBlowFishECB is legacy, consider using EvpAES128ECB instead
    if OpenSSL.version_number() ≥ v"3"
        OpenSSL.load_legacy_provider()
    end
    evp_cipher = EvpBlowFishECB()
    sym_key = random_bytes(evp_cipher.key_length ÷ 2)
    init_vector = random_bytes(evp_cipher.init_vector_length ÷ 2)

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
    server_task = @async test_server()
    client_task = @async test_client()
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
