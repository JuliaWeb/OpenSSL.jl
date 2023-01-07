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
        finalizer(free, ssl)

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

macro atomicget(ex)
    @static if VERSION < v"1.7"
        return esc(Expr(:ref, ex))
    else
        return esc(:(@atomic $ex))
    end
end

macro atomicset(ex)
    @static if VERSION < v"1.7"
        ex.args[1] = Expr(:ref, ex.args[1])
        return esc(ex)
    else
        return esc(:(@atomic $ex))
    end
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
    lock::ReentrantLock
@static if VERSION < v"1.7"
    close_notify_received::Threads.Atomic{Bool}
    closed::Threads.Atomic{Bool}
else
    @atomic close_notify_received::Bool
    @atomic closed::Bool
end

    function SSLStream(ssl_context::SSLContext, io::TCPSocket)
        # Create a read and write BIOs.
        bio_read::BIO = BIO(io; finalize=false)
        bio_write::BIO = BIO(io; finalize=false)
        ssl = SSL(ssl_context, bio_read, bio_write)

@static if VERSION < v"1.7"
        return new(ssl, ssl_context, bio_read, bio_write, io, ReentrantLock(), Threads.Atomic{Bool}(false), Threads.Atomic{Bool}(false))
else
        return new(ssl, ssl_context, bio_read, bio_write, io, ReentrantLock(), false, false)
end
    end
end

# backwards compat
SSLStream(ssl_context::SSLContext, io::TCPSocket, ::TCPSocket) = SSLStream(ssl_context, io)
Base.getproperty(ssl::SSLStream, nm::Symbol) = nm === :bio_read_stream ? ssl : getfield(ssl, nm)

SSLStream(tcp::TCPSocket) = SSLStream(SSLContext(OpenSSL.TLSClientMethod()), tcp)

Base.isreadable(ssl::SSLStream)::Bool = !(@atomicget(ssl.close_notify_received))
Base.isopen(ssl::SSLStream)::Bool = !@atomicget(ssl.closed)
Base.iswritable(ssl::SSLStream)::Bool = isopen(ssl) && isopen(ssl.io)
check_isopen(ssl::SSLStream, op) = isopen(ssl) || throw(Base.IOError("$op requires ssl to be open", 0))

macro geterror(expr)
    esc(quote
        ret = $expr
        if ret <= 0
            err = get_error(ssl.ssl, ret)
            if err == SSL_ERROR_ZERO_RETURN
                @atomicset ssl.close_notify_received = true
            elseif err == SSL_ERROR_NONE
                # pass
            elseif err == SSL_ERROR_WANT_READ
                ret = SSL_ERROR_WANT_READ
            elseif err == SSL_ERROR_WANT_WRITE
                ret = SSL_ERROR_WANT_WRITE
            else
                close(ssl, false)
                throw(Base.IOError(OpenSSLError(err).msg, 0))
            end
        end
    end)
end

function Base.unsafe_write(ssl::SSLStream, in_buffer::Ptr{UInt8}, in_length::UInt)
    check_isopen(ssl, "unsafe_write")
    @geterror ccall(
        (:SSL_write, libssl),
        Cint,
        (SSL, Ptr{Cvoid}, Cint),
        ssl.ssl,
        in_buffer,
        in_length
    )
    return ret
end

function Sockets.connect(ssl::SSLStream; require_ssl_verification::Bool=true)
    while true
        check_isopen(ssl, "connect")
        @geterror ssl_connect(ssl.ssl)
        if (ret == 1 || ret == SSL_ERROR_NONE)
            break
        elseif ret == SSL_ERROR_WANT_READ
            if eof(ssl.io)
                throw(EOFError())
            end
        else
            throw(Base.IOError(OpenSSLError(ret).msg, 0))
        end
    end

    # Check the certificate.
    if require_ssl_verification
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
        # get peer certificate
        cert = get_peer_certificate(ssl)
        cert === nothing && throw(OpenSSLError("No peer certificate"))
    end

    # set read ahead
    ccall(
        (:SSL_set_read_ahead, libssl),
        Cvoid,
        (SSL, Cint),
        ssl.ssl,
        Cint(1))
    return
end

const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
const TLSEXT_NAMETYPE_host_name = 0

function hostname!(ssl::SSLStream, host)
    # SSL_set_tlsext_host_name
    if (ret = ccall(
        (:SSL_ctrl, libssl),
        Cint,
        (SSL, Cint, Clong, Cstring),
        ssl.ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, host)) != 1
        throw(OpenSSLError(get_error()))
    end
    ssl_set_host(ssl.ssl, host)
end

function Sockets.accept(ssl::SSLStream)
    ssl_accept(ssl.ssl)
end

"""
    Read from the SSL stream.
"""
function Base.unsafe_read(ssl::SSLStream, buf::Ptr{UInt8}, nbytes::UInt)
    nread = 0
    while nread < nbytes
        (!isopen(ssl) || eof(ssl)) && throw(EOFError())
        readbytes = Ref{Csize_t}()
        @geterror ccall(
            (:SSL_read_ex, libssl),
            Cint,
            (SSL, Ptr{Int8}, Csize_t, Ptr{Csize_t}),
            ssl.ssl,
            buf + nread,
            nbytes - nread,
            readbytes
        )
        nread += Int(readbytes[])
    end
    return nread
end

function Base.readavailable(ssl::SSLStream)
    N = bytesavailable(ssl)
    buf = Vector{UInt8}(undef, N)
    n = unsafe_read(ssl, pointer(buf), N)
    return resize!(buf, n)
end

function Base.bytesavailable(ssl::SSLStream)::Cint
    isopen(ssl) || return 0
    pending_count = ccall(
        (:SSL_pending, libssl),
        Cint,
        (SSL,),
        ssl.ssl)
    update_tls_error_state()
    return pending_count
end

function haspending(s::SSLStream)
    isopen(s) || return false
    has_pending = ccall(
        (:SSL_has_pending, libssl),
        Cint,
        (SSL,),
        s.ssl)
    update_tls_error_state()
    return has_pending == 1
end

const PEEK_REF = Ref{UInt8}(0x00)

function Base.eof(ssl::SSLStream)::Bool
    bytesavailable(ssl) > 0 && return false
    Base.@lock ssl.lock begin
        # check if we're open inside the lock in case ssl got closed
        # in `close` while we were waiting for the lock
        isopen(ssl) || return true
        while isreadable(ssl) && bytesavailable(ssl) <= 0
            # no processed bytes available, check if there are unprocessed bytes
            if !haspending(ssl)
                # no unprocessed bytes, call eof to get more unprocessed
                if eof(ssl.io) && !haspending(ssl)
                    # if eof and there are no pending, then we are eof
                    return true
                end
            end
            # if we're here, we know there are unprocessed bytes,
            # so we call peek to force processing
            @geterror ccall(
                (:SSL_peek, libssl),
                Cint,
                (SSL, Ref{UInt8}, Cint),
                ssl.ssl,
                PEEK_REF,
                1
            )
            # if we get WANT_READ back, that means there were pending bytes
            # to be processed, but not a full record, so we need to wait
            # for additional bytes to come in before we can process
            ret == SSL_ERROR_WANT_READ && eof(ssl.io)
        end
    end
    bytesavailable(ssl) > 0 && return false
    return !isreadable(ssl)
end

"""
    Close SSL stream.
"""
function Base.close(ssl::SSLStream, shutdown::Bool=true)
    # eager unconditional closed set so other concurrent operations see it immediately
    @atomicset ssl.closed = true
    # if we've already finalized, no further action needed
    ssl.ssl.ssl == C_NULL && return
    # close operations
    Base.@lock ssl.lock begin
        # we do an additional check once inside the lock in case
        # it was closed while we were waiting on the lock
        isopen(ssl) || return
        # Ignore the disconnect result.
        shutdown && ssl_disconnect(ssl.ssl)
        # close underlying io
        try
            Base.close(ssl.io)
        catch e
            e isa Base.IOError || rethrow()
        end
        finalize(ssl.ssl)
    end
    return
end

"""
    Gets the X509 certificate of the peer.
"""
function get_peer_certificate(ssl::SSLStream)::Option{X509Certificate}
    x509 = ccall(
        (:SSL_get_peer_certificate, libssl),
        Ptr{Cvoid},
        (SSL,),
        ssl.ssl)
    if x509 != C_NULL
        return X509Certificate(x509)
    else
        return nothing
    end
end
