using Dates
using OpenSSL
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

function test()
    file_handle = open(MozillaCACerts_jll.cacert)
    file_content = String(read(file_handle))
    close(file_handle)

    start_line = "==========\n"

    certs_pem = split(file_content, start_line; keepempty=false)
    cert = certs_pem[2]

    x509_cert = OpenSSL.X509Certificate(cert)
    @test String(x509_cert.subject_name) == "/C=BE/O=GlobalSign nv-sa/OU=Root CA/CN=GlobalSign Root CA"
    @test String(x509_cert.issuer_name) == "/C=BE/O=GlobalSign nv-sa/OU=Root CA/CN=GlobalSign Root CA"
end

@testset "HttpsConnect" begin
    tcp_stream = connect("www.nghttp2.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)

    #TODO expose connect
    @show result = OpenSSL.connect(ssl_stream)

    x509_server_cert = OpenSSL.get_peer_certificate(ssl_stream)

    @test String(x509_server_cert.issuer_name) == "/C=US/O=Let's Encrypt/CN=R3"
    @test String(x509_server_cert.subject_name) == "/CN=nghttp2.org"

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

    written = unsafe_write(ssl_stream, pointer(request_str), length(request_str))

    response = read(ssl_stream)
    @show String(response)

    close(ssl_stream)
    finalize(ssl_ctx)
end

@testset "ClosedConnection" begin
    tcp_stream = connect("www.nghttp2.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)

    result = OpenSSL.connect(ssl_stream)
    @show result

    # Close the ssl stream.
    close(ssl_stream)

    request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

    err = @catch_exception_object unsafe_write(ssl_stream, pointer(request_str), length(request_str))
    @test typeof(err) == Base.IOError

    finalize(ssl_ctx)
end

@testset "Hash" begin
    res = digest(EVPMD5(), IOBuffer("The quick brown fox jumps over the lazy dog"))
    @test res == UInt8[0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6,]
end

@testset "HashOnIOStream" begin
    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    tcp_stream = connect("www.nghttp2.org", 443)
    ssl_stream = SSLStream(ssl_ctx, tcp_stream, tcp_stream)

    res = digest(EVPMD5(), ssl_stream)
    @show res
    close(ssl_stream)
    finalize(ssl_ctx)
end

@testset "SelfSignedCert" begin
    evp_pkey = EvpPKey(rsa_generate_key())
    x509_certificate = X509Certificate()
    x509_name = X509Name() # get_subject_name(x509_certificate)
    add_entry(x509_name, "C", "US")
    add_entry(x509_name, "ST", "Isles of Redmond")
    add_entry(x509_name, "CN", "www.redmond.com")

    adjust(x509_certificate.time_not_before, Second(0))
    adjust(x509_certificate.time_not_after, Year(1))

    x509_certificate.subject_name = x509_name
    x509_certificate.issuer_name = x509_name

    sign_certificate(x509_certificate, evp_pkey)

    @show OpenSSL.get_time_not_before(x509_certificate)
    @show OpenSSL.get_time_not_after(x509_certificate)

    iob = IOBuffer()

    write(iob, x509_certificate)

    seek(iob, 0)
    @show String(read(iob))

    @show x509_name, String(x509_name)
    @show x509_certificate
end
