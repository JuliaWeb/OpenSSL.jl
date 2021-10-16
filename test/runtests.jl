using Dates
using OpenSSL
using OpenSSL_jll
using Sockets
using Test

using MozillaCACerts_jll

macro catch_exception_object(code)
    quote
        err = try
            $(esc(code))
            nothing
        catch e
            e
        end
        if err == nothing
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
    OpenSSL.adjust(asn1_time, Dates.Second(4))

    OpenSSL.free(asn1_time)
    @test String(asn1_time) == "C_NULL"

    # double free
    OpenSSL.free(asn1_time)
    @test String(asn1_time) == "C_NULL"

    OpenSSL.adjust(asn1_time, Dates.Second(4))
    OpenSSL.adjust(asn1_time, Dates.Second(4))
    OpenSSL.adjust(asn1_time, Dates.Day(4))
    OpenSSL.adjust(asn1_time, Dates.Year(2))

    @show asn1_time
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
        OpenSSL.push(x509_certificates, x509_cert)
        finalize(x509_cert)
        nothing
    end

    free(x509_certificates)
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
    tcp_stream = connect("www.nghttp2.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)

    #TODO expose connect
    OpenSSL.connect(ssl_stream)

    x509_server_cert = OpenSSL.get_peer_certificate(ssl_stream)

    @test String(x509_server_cert.issuer_name) == "/C=US/O=Let's Encrypt/CN=R3"
    @test String(x509_server_cert.subject_name) == "/CN=nghttp2.org"

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

    written = unsafe_write(ssl_stream, pointer(request_str), length(request_str))

    response = read(ssl_stream)

    close(ssl_stream)
    finalize(ssl_ctx)
end

@testset "ClosedStream" begin
    tcp_stream = connect("www.nghttp2.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)
    OpenSSL.ssl_set_ciphersuites(ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")

    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)

    OpenSSL.connect(ssl_stream)

    # Close the ssl stream.
    close(ssl_stream)

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

    err = @catch_exception_object unsafe_write(ssl_stream, pointer(request_str), length(request_str))
    @test typeof(err) == Base.IOError

    finalize(ssl_ctx)
end

@testset "NoCloseStream" begin
    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    tcp_stream = connect("www.nghttp2.org", 443)
    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)
    OpenSSL.connect(ssl_stream)

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"
    unsafe_write(ssl_stream, pointer(request_str), length(request_str))

    response = read(ssl_stream)
    @test contains(String(response), "HTTP/1.1 200 OK")

    # Do not close SSLStream, leave it to the finalizer.
    #close(ssl_stream)
    #finalize(ssl_ctx)
end

@testset "InvalidStream" begin
    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    tcp_stream = connect("www.nghttp2.org", 443)
    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)

    err = @catch_exception_object read(ssl_stream)
    @test typeof(err) == OpenSSL.OpenSSLError

    close(ssl_stream)
    free(ssl_ctx)
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

    adjust(x509_certificate.time_not_before, Second(0))
    adjust(x509_certificate.time_not_after, Year(1))

    add_extension(x509_certificate, X509Extension("basicConstraints", "CA:TRUE"))
    add_extension(x509_certificate, X509Extension("keyUsage", "keyCertSign"))

    sign_certificate(x509_certificate, evp_pkey)

    iob = IOBuffer()
    write(iob, x509_certificate)

    seek(iob, 0)
    cert_pem = String(read(iob))

    x509_certificate2 = X509Certificate(cert_pem)

    x509_string = String(x509_certificate)
    x509_string2 = String(x509_certificate2)

    public_key = x509_certificate.public_key

    @test x509_string == x509_string2

    p12_object = P12Object(evp_pkey, x509_certificate)

    OpenSSL.unpack(p12_object)

    #seek(io, 0)
    # @show "p12:" String(read(io))
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

    adjust(x509_certificate.time_not_before, Second(0))
    adjust(x509_certificate.time_not_after, Year(1))

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
    OpenSSL.push(x509_exts, ext)
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

    ext = OpenSSL.pop(x509_exts)

    add_extension(x509_certificate, ext)
    add_extension(x509_certificate, X509Extension("keyUsage", "digitalSignature, nonRepudiation, keyEncipherment"))
    add_extension(x509_certificate, X509Extension("basicConstraints", "CA:FALSE"))

    # Set public key
    x509_certificate.public_key = x509_request.public_key

    adjust(x509_certificate.time_not_before, Second(0))
    adjust(x509_certificate.time_not_after, Year(1))

    sign_certificate(x509_certificate, evp_pkey_ca)
end

@testset "ErrorTaskTLS" begin
    err_msg = OpenSSL.get_error()
    @test err_msg == ""

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ServerMethod())

    # Make direct invalid call to OpenSSL
    invalid_cipher_suites = "TLS_AES_356_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
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

function test_server()
    x509_certificate = X509Certificate()

    evp_pkey = EvpPKey(rsa_generate_key())
    x509_certificate.public_key = evp_pkey

    x509_name = X509Name()
    add_entry(x509_name, "C", "US")
    add_entry(x509_name, "ST", "Isles of Redmond")
    add_entry(x509_name, "CN", "www.redmond.com")

    adjust(x509_certificate.time_not_before, Second(0))
    adjust(x509_certificate.time_not_after, Year(1))

    x509_certificate.subject_name = x509_name
    x509_certificate.issuer_name = x509_name

    sign_certificate(x509_certificate, evp_pkey)

    server_socket = listen(5000)
    accepted_socket = accept(server_socket)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ServerMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)
    @show result
    result = OpenSSL.ssl_set_ciphersuites(ssl_ctx,
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
    @show result

    result = OpenSSL.ssl_use_certificate(ssl_ctx, x509_certificate)
    @show result

    result = OpenSSL.ssl_use_private_key(ssl_ctx, evp_pkey)
    @show result

    ssl_stream = SSLStream(ssl_ctx, accepted_socket, accepted_socket)
    @show ssl_stream

    OpenSSL.accept(ssl_stream)

    eof(ssl_stream)
    av = bytesavailable(ssl_stream)
    request = read(ssl_stream, av)
    reply = "reply: $(String(request))"

    write(ssl_stream, reply)

    close(ssl_stream)
    finalize(ssl_ctx)
    return nothing
end

function test_client()
    tcp_stream = connect(5000)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)

    #TODO expose connect
    OpenSSL.connect(ssl_stream)

    x509_server_cert = OpenSSL.get_peer_certificate(ssl_stream)

    @test String(x509_server_cert.issuer_name) == "/C=US/ST=Isles of Redmond/CN=www.redmond.com"
    @test String(x509_server_cert.subject_name) == "/C=US/ST=Isles of Redmond/CN=www.redmond.com"

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

    written = unsafe_write(ssl_stream, pointer(request_str), length(request_str))

    response = read(ssl_stream)
    @show String(response)

    close(ssl_stream)
    finalize(ssl_ctx)
    return nothing
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

    adjust(x509_certificate.time_not_before, Second(0))
    adjust(x509_certificate.time_not_after, Year(1))

    sign_certificate(x509_certificate, evp_pkey)

    p12_object = P12Object(evp_pkey, x509_certificate)

    #open("file.p12", "a") do io
    #    write(io, p12_object)
    #end
end

@testset "Encrypt" begin
    sym_key = random_bytes(OpenSSL.EVP_MAX_KEY_LENGTH)
    init_vec = random_bytes(OpenSSL.EVP_MAX_IV_LENGTH)

    enc_evp_cipher_ctx = EvpCipherContext()
    encrypt_init(enc_evp_cipher_ctx, EvpBlowFishCBC(), sym_key, init_vec)

    dec_evp_cipher_ctx = EvpCipherContext()
    decrypt_init(dec_evp_cipher_ctx, EvpBlowFishCBC(), sym_key, init_vec)

    in_data = IOBuffer("ala ma kota 4i4pi34i45434341234567890abcd_")
    enc_data = IOBuffer()

    cipher(enc_evp_cipher_ctx, in_data, enc_data)
    seek(enc_data, 0)
    @show String(read(enc_data))
    seek(enc_data, 0)

    dec_data = IOBuffer()
    cipher(dec_evp_cipher_ctx, enc_data, dec_data)
    @show String(take!(dec_data))
    seek(dec_data, 0)

    @test 1 == 1
end

@testset "StackOf{X509Extension}" begin
    ext1 = X509Extension("subjectAltName", "DNS:openssl.jl.com")
    ext2 = X509Extension("keyUsage", "digitalSignature, keyEncipherment, keyAgreement")
    ext3 = X509Extension("basicConstraints", "CA:FALSE")

    st = StackOf{X509Extension}()
    OpenSSL.push(st, ext1)
    OpenSSL.push(st, ext2)
    OpenSSL.push(st, ext3)

    @test String(ext1) == "DNS:openssl.jl.com"
    @test String(ext2) == "Digital Signature, Key Encipherment, Key Agreement"
    @test String(ext3) == "CA:FALSE"

    finalize(ext1)
    finalize(ext2)
    finalize(ext3)

    @test length(st) == 3

    ext_1 = OpenSSL.pop(st)
    ext_2 = OpenSSL.pop(st)
    ext_3 = OpenSSL.pop(st)

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
    write(io, evp_pkey)

    seek(io, 0)
    pem = String(read(io))
    @show pem

    free(evp_pkey)
end

@testset "DSA" begin
    dsa = dsa_generate_key()
end
