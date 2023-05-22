using Dates
using OpenSSL
using Sockets
using Test

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

    # Create and configure server SSLContext.
    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSServerMethod())
    _ = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    OpenSSL.ssl_set_ciphersuites(ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
    OpenSSL.ssl_use_certificate(ssl_ctx, x509_certificate)
    OpenSSL.ssl_use_private_key(ssl_ctx, evp_pkey)

    server_socket = listen(5000)
    accepted_socket = accept(server_socket)

    ssl = SSLStream(ssl_ctx, accepted_socket)

    OpenSSL.accept(ssl)

    # wait for the request, as we are using `readavailable`
    # we need to make sure there is a data in the buffer.
    while bytesavailable(ssl) == 0
        eof(ssl)
    end

    request = readavailable(ssl)
    reply = "reply: $(String(request))"

    # eof(ssl) will block

    # Verify the are no more bytes available in the stream.
    @test bytesavailable(ssl) == 0

    unsafe_write(ssl, pointer(reply), length(reply))

    # Wait for the client confirmation then disconnect.
    while bytesavailable(ssl) == 0
        eof(ssl)
    end

    close(ssl)
    finalize(ssl_ctx)

    return nothing
end

function test_client()
    tcp_stream = connect(5000)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())
    _ = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    ssl = SSLStream(ssl_ctx, tcp_stream)

    connect(ssl; require_ssl_verification = false)

    # Verify the server certificate.
    x509_server_cert = OpenSSL.get_peer_certificate(ssl)

    @test String(x509_server_cert.issuer_name) == "/C=US/ST=Isles of Redmond/CN=www.redmond.com"
    @test String(x509_server_cert.subject_name) == "/C=US/ST=Isles of Redmond/CN=www.redmond.com"

    request_str = "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\nRequest_body."

    written = unsafe_write(ssl, pointer(request_str), length(request_str))
    @test length(request_str) == written

    # wait for the response.
    while bytesavailable(ssl) == 0
        eof(ssl)
    end

    response_str = String(readavailable(ssl))

    @test response_str == "reply: $(request_str)"
    @show response_str

    # Send a message again, that is the information for the server to disonnect.
    written = unsafe_write(ssl, pointer(request_str), length(request_str))

    close(ssl)
    finalize(ssl_ctx)
end
