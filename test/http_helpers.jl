using Dates
using OpenSSL
using Sockets

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
    try
        accepted_socket = accept(server_socket)

        # Create and configure server SSLContext.
        ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSServerMethod())
        _ = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

        OpenSSL.ssl_set_ciphersuites(ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
        OpenSSL.ssl_use_certificate(ssl_ctx, x509_certificate)
        OpenSSL.ssl_use_private_key(ssl_ctx, evp_pkey)

        ssl = SSLStream(ssl_ctx, accepted_socket)

        OpenSSL.accept(ssl)

        @test !eof(ssl)
        request = readavailable(ssl)
        reply = "reply: $(String(request))"

        # eof(ssl) will block

        # Verify the are no more bytes available in the stream.
        @test bytesavailable(ssl) == 0

        write(ssl, reply)

        try
            close(ssl)
        catch
        end
        finalize(ssl_ctx)
    finally
        close(server_socket)
    end
    return nothing
end

function test_client()
    tcp_stream = connect(5000)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())
    ssl_options = OpenSSL.ssl_set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

    # Create SSL stream.
    ssl = SSLStream(ssl_ctx, tcp_stream)

    #TODO expose connect
    OpenSSL.connect(ssl)

    # Verify the server certificate.
    x509_server_cert = OpenSSL.get_peer_certificate(ssl)

    @test String(x509_server_cert.issuer_name) == "/C=US/ST=Isles of Redmond/CN=www.redmond.com"
    @test String(x509_server_cert.subject_name) == "/C=US/ST=Isles of Redmond/CN=www.redmond.com"

    request_str = "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\nRequest_body."

    written = unsafe_write(ssl, pointer(request_str), length(request_str))

    sleep(1)
    @test !eof(ssl)
    @test length(request_str) == written

    response_str = String(readavailable(ssl))

    @test response_str == "reply: $request_str"

    try
        close(ssl)
    catch
    end
    finalize(ssl_ctx)
    return nothing
end
