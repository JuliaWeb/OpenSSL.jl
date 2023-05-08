"""
    BIO Stream callbacks.
"""

"""
    Called to initialize new BIO Stream object.
"""
on_bio_stream_create(bio::BIO) = Cint(1)
on_bio_stream_destroy(bio::BIO)::Cint = Cint(0)

function bio_get_data(bio::BIO)
    data = ccall(
        (:BIO_get_data, libcrypto),
        Ptr{Cvoid},
        (BIO,),
        bio)
    return unsafe_pointer_to_objref(data)
end

const BIO_FLAGS_SHOULD_RETRY = 0x08
const BIO_FLAGS_READ = 0x01
const BIO_FLAGS_WRITE = 0x02
const BIO_FLAGS_IO_SPECIAL = 0x04

function bio_set_flags(bio::BIO, flags)
    return ccall(
        (:BIO_set_flags, libcrypto),
        Cint,
        (BIO, Cint),
        bio, flags)
end
bio_set_read_retry(bio::BIO) = bio_set_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY)
bio_clear_flags(bio::BIO) = bio_set_flags(bio, 0x00)

function on_bio_stream_read(bio::BIO, out::Ptr{Cchar}, outlen::Cint)
    try
        bio_clear_flags(bio)
        io = bio_get_data(bio)::TCPSocket
        n = bytesavailable(io)
        if n == 0
            bio_set_read_retry(bio)
            return Cint(0)
        end
        unsafe_read(io, out, min(UInt(n), outlen))
        return Cint(min(n, outlen))
    catch e
        # we don't want to throw a Julia exception from a C callback
        return Cint(0)
    end
end

function on_bio_stream_write(bio::BIO, in::Ptr{Cchar}, inlen::Cint)::Cint
    try
        io = bio_get_data(bio)::TCPSocket
        written = unsafe_write(io, in, inlen)
        return Cint(written)
    catch e
        # we don't want to throw a Julia exception from a C callback
        return Cint(0)
    end
end

on_bio_stream_puts(bio::BIO, in::Ptr{Cchar})::Cint = Cint(0)

on_bio_stream_ctrl(bio::BIO, cmd::BIOCtrl, num::Clong, ptr::Ptr{Cvoid}) = Clong(1)

"""
    BIO Stream callbacks.
"""
struct BIOStreamCallbacks
    on_bio_create_ptr::Ptr{Nothing}
    on_bio_destroy_ptr::Ptr{Nothing}
    on_bio_read_ptr::Ptr{Nothing}
    on_bio_write_ptr::Ptr{Nothing}
    on_bio_puts_ptr::Ptr{Nothing}
    on_bio_ctrl_ptr::Ptr{Nothing}

    function BIOStreamCallbacks()
        on_bio_create_ptr = @cfunction on_bio_stream_create Cint (BIO,)
        on_bio_destroy_ptr = @cfunction on_bio_stream_destroy Cint (BIO,)
        on_bio_read_ptr = @cfunction on_bio_stream_read Cint (BIO, Ptr{Cchar}, Cint)
        on_bio_write_ptr = @cfunction on_bio_stream_write Cint (BIO, Ptr{Cchar}, Cint)
        on_bio_puts_ptr = @cfunction on_bio_stream_puts Cint (BIO, Ptr{Cchar})
        on_bio_ctrl_ptr = @cfunction on_bio_stream_ctrl Clong (BIO, BIOCtrl, Clong, Ptr{Cvoid})

        return new(
            on_bio_create_ptr,
            on_bio_destroy_ptr,
            on_bio_read_ptr,
            on_bio_write_ptr,
            on_bio_puts_ptr,
            on_bio_ctrl_ptr)
    end
end

"""
    SSLMethod.
    TLSClientMethod.
"""
mutable struct SSLMethod
    ssl_method::Ptr{Cvoid}
end

function TLSClientMethod()
    ssl_method = ccall(
        (:TLS_client_method, libssl),
        Ptr{Cvoid},
        ())
    if ssl_method == C_NULL
        throw(OpenSSLError())
    end

    return SSLMethod(ssl_method)
end

function TLSServerMethod()
    ssl_method = ccall(
        (:TLS_server_method, libssl),
        Ptr{Cvoid},
        ())
    if ssl_method == C_NULL
        throw(OpenSSLError())
    end

    return SSLMethod(ssl_method)
end

const SSL_MODE_AUTO_RETRY = 0x00000004

"""
    This is the global context structure which is created by a server or client once per program life-time
    and which holds mainly default values for the SSL structures which are later created for the connections.
"""
mutable struct SSLContext
    ssl_ctx::Ptr{Cvoid}

    function SSLContext(ssl_method::SSLMethod, verify_file::String=MozillaCACerts_jll.cacert)
        ssl_ctx = ccall(
            (:SSL_CTX_new, libssl),
            Ptr{Cvoid},
            (SSLMethod,),
            ssl_method)
        if ssl_ctx == C_NULL
            throw(OpenSSLError())
        end

        ssl_context = new(ssl_ctx)
        finalizer(free, ssl_context)

        # set auto retry mode
        ccall(
            (:SSL_CTX_ctrl, libssl),
            Cint,
            (SSLContext, Cint, Clong, Ptr{Cvoid}),
            ssl_context, 33, SSL_MODE_AUTO_RETRY, C_NULL)
        if !isempty(verify_file)
            @assert ccall(
                (:SSL_CTX_load_verify_locations, libssl),
                Cint,
                (SSLContext, Ptr{Cchar}, Ptr{Cchar}),
                ssl_context,
                verify_file,
                C_NULL) == 1
        end

        return ssl_context
    end
end

function ca_chain!(ssl_context::SSLContext, cacert::String)
    ccall(
        (:SSL_CTX_load_verify_locations, libssl),
        Cint,
        (SSLContext, Ptr{Cchar}, Ptr{Cchar}),
        ssl_context,
        cacert,
        C_NULL)
end

function free(ssl_context::SSLContext)
    ssl_context.ssl_ctx == C_NULL && return
    ccall(
        (:SSL_CTX_free, libssl),
        Cvoid,
        (SSLContext,),
        ssl_context)

    ssl_context.ssl_ctx = C_NULL
    return
end

"""
    Sets the (external) protocol behaviour of the SSL library.
"""
function ssl_set_options(ssl_context::SSLContext, options::SSLOptions)::SSLOptions
    return ccall(
        (:SSL_CTX_set_options, libssl),
        SSLOptions,
        (SSLContext, SSLOptions),
        ssl_context,
        options)
end

"""
    Configures TLS ALPN (Application-Layer Protocol Negotiation).
"""
function ssl_set_alpn(ssl_context::SSLContext, protocol_list::String)
    if ccall(
        (:SSL_CTX_set_alpn_protos, libssl),
        Cint,
        (SSLContext, Ptr{UInt8}, UInt32),
        ssl_context,
        pointer(protocol_list),
        length(protocol_list)) != 0
        throw(OpenSSLError())
    end
end

"""
    Sets minimum supported protocol version for SSLContext.
"""
function ssl_set_min_protocol_version(ssl_context::SSLContext, version::TlsVersion)
    if ccall(
        (:SSL_CTX_ctrl, libssl),
        Cint,
        (SSLContext, SSLControlCommand, TlsVersion, Ptr{Cvoid}),
        ssl_context,
        SSL_CTRL_SET_MIN_PROTO_VERSION,
        version,
        C_NULL) != 1
        throw(OpenSSLError())
    end
end

# TODO
# int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);

"""
    Configures available TLSv1.3 cipher suites.
"""
function ssl_set_ciphersuites(ssl_context::SSLContext, cipher_suites::String)
    if ccall(
        (:SSL_CTX_set_ciphersuites, libssl),
        Cint,
        (SSLContext, Cstring),
        ssl_context,
        cipher_suites) != 1
        throw(OpenSSLError())
    end
end

function ssl_use_certificate(ssl_context::SSLContext, x509_cert::X509Certificate)
    if ccall(
        (:SSL_CTX_use_certificate, libssl),
        Cint,
        (SSLContext, X509Certificate),
        ssl_context,
        x509_cert) != 1
        throw(OpenSSLError())
    end
end

function ssl_use_private_key(ssl_context::SSLContext, evp_pkey::EvpPKey)
    if ccall(
        (:SSL_CTX_use_PrivateKey, libssl),
        Cint,
        (SSLContext, EvpPKey),
        ssl_context,
        evp_pkey) != 1
        throw(OpenSSLError())
    end
end

"""
    SSL structure for a connection.
"""
mutable struct SSL
    ssl::Ptr{Cvoid}

    function SSL(ssl_context::SSLContext, read_bio::BIO, write_bio::BIO)::SSL
        ssl = ccall(
            (:SSL_new, libssl),
            Ptr{Cvoid},
            (SSLContext,),
            ssl_context)
        if ssl == C_NULL
            throw(OpenSSLError())
        end

        ssl = new(ssl)

        ccall(
            (:SSL_set_bio, libssl),
            Cvoid,
            (SSL, BIO, BIO),
            ssl,
            read_bio,
            write_bio)

        return ssl
    end
end

function free(ssl::SSL)
    ssl.ssl == C_NULL && return
    ccall(
        (:SSL_free, libssl),
        Cvoid,
        (SSL,),
        ssl)

    ssl.ssl = C_NULL
    return
end

function ssl_set_host(ssl::SSL, host)
    if (ret = ccall(
        (:SSL_set1_host, libssl),
        Cint,
        (SSL, Cstring),
        ssl, host)) != 1
        throw(OpenSSLError(ret))
    end
end

function ssl_connect(ssl::SSL)
    return ccall(
        (:SSL_connect, libssl),
        Cint,
        (SSL,),
        ssl)
end

function ssl_accept(ssl::SSL)
    if (ret = ccall(
        (:SSL_accept, libssl),
        Cint,
        (SSL,),
        ssl)) != 1
        throw(OpenSSLError(ret))
    end

    ccall(
        (:SSL_set_read_ahead, libssl),
        Cvoid,
        (SSL, Cint),
        ssl,
        Int32(1))
    return nothing
end

"""
    Shut down a TLS/SSL connection.
"""
function ssl_disconnect(ssl::SSL)
    ccall(
        (:SSL_shutdown, libssl),
        Cint,
        (SSL,),
        ssl)
    return nothing
end

function get_error(ssl::SSL, ret::Cint)::SSLErrorCode
    return ccall(
        (:SSL_get_error, libssl),
        SSLErrorCode,
        (SSL, Cint),
        ssl,
        ret)
end

"""
    SSLStream.
"""
mutable struct SSLStream <: IO
    ssl::SSL
    ssl_context::SSLContext
    rbio::BIO
    wbio::BIO
    io::TCPSocket
    # used in `eof` where we want the call to `eof` on the underlying
    # socket and the SSL_peek call that processes bytes to be seen
    # as one "operation"
    eoflock::ReentrantLock
    # this lock guards operations accessing our .ssl object and after acquiring
    # the lock, *MUST* check if .closed is true before proceeding
    # also this guards against 2 threads trying to
    # call `read` or `write` at the same time as per the thread in
    # https://mailing.openssl.users.narkive.com/HeNGlNAJ/openssl-and-multithreaded-programs
    lock::ReentrantLock
    readbytes::Base.RefValue{Csize_t}
    writebytes::Base.RefValue{Csize_t}
    peekbuf::Base.RefValue{UInt8}
    peekbytes::Base.RefValue{Csize_t}
    closed::Bool

    function SSLStream(ssl_context::SSLContext, io::TCPSocket)
        # Create a read and write BIOs.
        bio_read::BIO = BIO(io; finalize=false)
        bio_write::BIO = BIO(io; finalize=false)
        ssl = SSL(ssl_context, bio_read, bio_write)
        return new(ssl, ssl_context, bio_read, bio_write, io, ReentrantLock(), ReentrantLock(), Ref{Csize_t}(0), Ref{Csize_t}(0), Ref{UInt8}(0x00), Ref{Csize_t}(0), false)
    end
end

SSLStream(tcp::TCPSocket) = SSLStream(SSLContext(OpenSSL.TLSClientMethod()), tcp)

# backwards compat
Base.getproperty(ssl::SSLStream, nm::Symbol) = nm === :bio_read_stream ? ssl : getfield(ssl, nm)

Base.isreadable(ssl::SSLStream)::Bool = isopen(ssl) && isreadable(ssl.io)
Base.isopen(ssl::SSLStream)::Bool = Base.@lock(ssl.lock, !ssl.closed)
Base.iswritable(ssl::SSLStream)::Bool = isopen(ssl) && isopen(ssl.io)
@noinline throwio(op) = throw(Base.IOError("$op requires ssl to be open", 0))

# this is a macro, but should be a function, but closures are stupid slow
# we use this to standardize the error handling for all of the SSL_*_ex functions
macro geterror(ssl, op, expr)
    esc(quote
        # lock our SSLStream while we clear errors
        # make a ccall, then check the error queue
        Base.@lock ssl.lock begin
            # check that SSL is still open before ccall
            $ssl.closed && throwio($op)
            # clear the current error queue before openssl ccall
            clear_errors!()
            # do the ccall
            _ret = $expr
            # we want to return one of our SSL return codes, regardless of error
            # SSL_peek_ex, SSL_write_ex, SSL_connect, and SSL_read_ex all return 1 on success
            if _ret == 1
                ret = SSL_ERROR_NONE
            else
                err = get_error($ssl.ssl, _ret)
                if err == SSL_ERROR_ZERO_RETURN
                    # the peer sent a close_notify, so no more reading is possible
                    close($ssl, false)
                    throw(Base.IOError("unexpected EOF", 0))
                elseif err == SSL_ERROR_NONE
                    ret = SSL_ERROR_NONE
                elseif err == SSL_ERROR_WANT_READ
                    # we need to read more data from the underlying socket
                    ret = SSL_ERROR_WANT_READ
                elseif err == SSL_ERROR_WANT_WRITE
                    # we need to write more data to the underlying socket
                    # we don't expect to ever see this since we set up our SSL
                    # to do auto TLS (re)negotiation
                    ret = SSL_ERROR_WANT_WRITE
                else
                    # this is usually some other kind of error, like a protocol error
                    # or OS-level IO error, just close the SSL connection and throw
                    # notably, the openssl docs say we should *not* call ssl_disconnect
                    # in this case, hence the `false` arg to close
                    close($ssl, false)
                    throw(Base.IOError(OpenSSLError(err).msg, 0))
                end
            end
            ret
        end
    end)
end

function Base.unsafe_write(ssl::SSLStream, in_buffer::Ptr{UInt8}, in_length::UInt)
    nwritten = 0
    while nwritten < in_length
        ret = @geterror ssl :unsafe_write ccall(
            (:SSL_write_ex, libssl),
            Cint,
            (SSL, Ptr{Cvoid}, Cint, Ptr{Csize_t}),
            ssl.ssl,
            in_buffer,
            in_length,
            ssl.writebytes
        )
        if ret == SSL_ERROR_NONE
            nwritten += ssl.writebytes[]
        elseif ret == SSL_ERROR_WANT_WRITE
            flush(ssl.io)
        elseif ret == SSL_ERROR_WANT_READ
            # this means write is waiting for more data from the underlying socket
            # so call eof on the socket to wait for more bytes to come in
            eof(ssl.io) && throw(EOFError())
        end
    end
    return Base.bitcast(Int, in_length)
end

function Sockets.connect(ssl::SSLStream; require_ssl_verification::Bool=true)
    while true
        ret = @geterror ssl :connect ssl_connect(ssl.ssl)
        if ret == SSL_ERROR_NONE
            break
        elseif ret == SSL_ERROR_WANT_READ
            # this means connect is waiting for more data from the underlying socket
            # so call eof on the socket to wait for more bytes to come in
            eof(ssl.io) && throw(EOFError())
        else
            throw(Base.IOError(OpenSSLError(ret).msg, 0))
        end
    end

    # Check the certificate.
    if require_ssl_verification
        Base.@lock ssl.lock begin
            ssl.closed && throwio(:verify_result)
            if (ret = ccall(
                (:SSL_get_verify_result, libssl),
                Cint,
                (SSL,),
                ssl.ssl)) != 0
                throw(OpenSSLError(unsafe_string(ccall(
                    (:X509_verify_cert_error_string, libcrypto),
                    Ptr{UInt8},
                    (Cint,),
                    ret))))
            end
        end
        # get peer certificate
        cert = get_peer_certificate(ssl)
        cert === nothing && throw(OpenSSLError("No peer certificate"))
    end

    # set read ahead; this is a recommended optimization when we can guarantee
    # that an SSL connection will only ever be read from sequentially, which we do
    # by not doing any internal buffering
    Base.@lock ssl.lock begin
        ssl.closed && throwio(:read_ahead)
        ccall(
            (:SSL_set_read_ahead, libssl),
            Cvoid,
            (SSL, Cint),
            ssl.ssl,
            Cint(1))
    end
    return
end

const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
const TLSEXT_NAMETYPE_host_name = 0

function hostname!(ssl::SSLStream, host)
    Base.@lock ssl.lock begin
        ssl.closed && throwio(:hostname)
        if (ret = ccall(
            (:SSL_ctrl, libssl),
            Cint,
            (SSL, Cint, Clong, Cstring),
            ssl.ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, host)) != 1
            throw(OpenSSLError(get_error()))
        end
        ssl_set_host(ssl.ssl, host)
    end
end

function Sockets.accept(ssl::SSLStream)
    ssl_accept(ssl.ssl)
end

"""
    Read from the SSL stream.
"""
function Base.unsafe_read(ssl::SSLStream, buf::Ptr{UInt8}, nbytes::UInt)
    nread = 0
    readbytes = ssl.readbytes
    while nread < nbytes
        ret = @geterror ssl :unsafe_read ccall(
            (:SSL_read_ex, libssl),
            Cint,
            (SSL, Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
            ssl.ssl,
            buf + nread,
            nbytes - nread,
            readbytes
        )
        if ret == SSL_ERROR_NONE
            nread += Base.bitcast(Int, readbytes[])
        elseif ret == SSL_ERROR_WANT_READ
            # this means write is waiting for more data from the underlying socket
            # so call eof on the socket to wait for more bytes to come in
            eof(ssl.io) && throw(EOFError())
        elseif ret == SSL_ERROR_WANT_WRITE
            flush(ssl.io)
        end
    end
    return nread
end

function Base.readavailable(ssl::SSLStream)
    N = bytesavailable(ssl)
    buf = Vector{UInt8}(undef, N)
    n = GC.@preserve buf unsafe_read(ssl, pointer(buf), N)
    return resize!(buf, n)
end

# returns the # of bytes that can be read immediately via unsafe_read
# i.e. # of processed, decrypted bytes available
function Base.bytesavailable(ssl::SSLStream)
    Base.@lock ssl.lock begin
        ssl.closed && return 0
        return Int(ccall(
            (:SSL_pending, libssl),
            Cint,
            (SSL,),
            ssl.ssl))
    end
end

# returns whether there are _any_ bytes buffered, processed
# or unprocessed, in the SSL stream
function haspending(ssl::SSLStream)
    Base.@lock ssl.lock begin
        ssl.closed && return false
        return 1 == ccall(
            (:SSL_has_pending, libssl),
            Cint,
            (SSL,),
            ssl.ssl)
    end
end

function Base.eof(ssl::SSLStream)::Bool
    bytesavailable(ssl) > 0 && return false
    while isopen(ssl)
        # note that care needs to be taken here to avoid a potential bad
        # race condition; for SSLStream, we have to manage the state of
        # the underlying socket having available bytes *and* whether they've
        # been processed in the ssl layer, so we want to treat the receiving and processing
        # of bytes as a single operation; in other words, bytesavailable returns
        # > 0 when bytes have been received *and* processed and we don't want
        # racing tasks to get stuck in between. We also don't really care whether
        # tasks are blocked calling eof on the socket or waiting on eoflock, so
        # we avoid the races and keep things orderly by only allowing one task
        # to make the eof call and kick off byte processing at a time.
        Base.@lock ssl.eoflock begin
            # check condition now that we have eoflock since another task may have
            # succeeded in getting bytes processed
            isopen(ssl) || return true
            bytesavailable(ssl) > 0 && return false
            # no processed bytes available, check if there are unprocessed bytes
            if !haspending(ssl)
                # no unprocessed bytes, call eof to get more unprocessed
                if eof(ssl.io) && !haspending(ssl)
                    # if eof and there are no pending, then we are eof
                    return true
                end
            end
            # at this point, we know there are at least unprocessed bytes
            # buffered, so we call SSL_peek to get the next record processed,
            # which still might not result in bytesavailable > 0
            ret = @geterror ssl :peek ccall(
                (:SSL_peek_ex, libssl),
                Cint,
                (SSL, Ptr{UInt8}, Cint, Ptr{Csize_t}),
                ssl.ssl,
                ssl.peekbuf,
                1,
                ssl.peekbytes
            )
            if ret == SSL_ERROR_NONE
                return false
            elseif ret == SSL_ERROR_WANT_WRITE
                flush(ssl.io)
            elseif ret == SSL_ERROR_WANT_READ
                # if we get WANT_READ back, that means there were pending bytes
                # to be processed, but not a full record, so we need to wait
                # for additional bytes to come in before we can process
                eof(ssl.io)
            end
        end
    end
    bytesavailable(ssl) > 0 && return false
    return !isopen(ssl)
end

"""
    Close SSL stream.
"""
function Base.close(ssl::SSLStream, shutdown::Bool=true)
    close_socket = false
    Base.@lock ssl.lock begin
        ssl.closed && return
        ssl.closed = true
        close_socket = true
        # Ignore the disconnect result.
        shutdown && ssl_disconnect(ssl.ssl)
        free(ssl.ssl)
    end
    if close_socket
        # close underlying io; because closing a TCPSocket may block
        # we do it outside holding the ssl.lock
        try
            Base.close(ssl.io)
        catch e
            e isa Base.IOError || rethrow()
        end
    end
    return
end

"""
    Gets the X509 certificate of the peer.
"""
function get_peer_certificate(ssl::SSLStream)::Option{X509Certificate}
    Base.@lock ssl.lock begin
        ssl.closed && throwio(:get_peer_certificate)
        x509 = ccall(
            (SSL_get_peer_certificate, libssl),
            Ptr{Cvoid},
            (SSL,),
            ssl.ssl)
        if x509 != C_NULL
            return X509Certificate(x509)
        else
            return nothing
        end
    end
end
