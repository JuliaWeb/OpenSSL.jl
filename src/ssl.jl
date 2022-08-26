"""
    BIO Stream callbacks.
"""

"""
    Called to initialize new BIO Stream object.
"""
function on_bio_stream_create(bio::BIO)::Cint
    # Initalize BIO.
    ccall(
        (:BIO_set_init, libcrypto),
        Cvoid,
        (BIO, Cint),
        bio,
        0)

    ccall(
        (:BIO_set_data, libcrypto),
        Cvoid,
        (BIO, Cint),
        bio,
        C_NULL)

    return Cint(1)
end

on_bio_stream_destroy(bio::BIO)::Cint = Cint(0)

function on_bio_stream_read(bio::BIO, out::Ptr{Cchar}, outlen::Cint)::Cint
    bio_stream = bio_stream_from_data(bio)

    eof(bio_stream.io)
    available_bytes = bytesavailable(bio_stream.io)

    outlen = min(outlen, available_bytes)

    unsafe_read(bio_stream.io, out, outlen)

    return outlen
end

function on_bio_stream_write(bio::BIO, in::Ptr{Cchar}, inlen::Cint)::Cint
    bio_stream = bio_stream_from_data(bio)

    written = unsafe_write(bio_stream.io, in, inlen)

    return Cint(written)
end

on_bio_stream_puts(bio::BIO, in::Ptr{Cchar})::Cint = Cint(0)

on_bio_stream_ctrl(bio::BIO, cmd::BIOCtrl, num::Int64, ptr::Ptr{Cvoid})::Int64 = 1

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
        on_bio_ctrl_ptr = @cfunction on_bio_stream_ctrl Int64 (BIO, BIOCtrl, Int64, Ptr{Cvoid})

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
    BIOStream.
"""
mutable struct BIOStream <: IO
    bio::BIO
    io::Option{IO}

    BIOStream(io::IO) = new(BIO(), io)

    BIOStream(bio::BIO, io::IO) = new(bio, io)
end

function bio_stream_set_data(bio_stream::BIOStream)
    # Ensure the BIO is valid.
    if bio_stream.bio.bio == C_NULL
        throw(Base.IOError("bio stream is closed or unusable", 0))
    end

    ccall(
        (:BIO_set_data, libcrypto),
        Cvoid,
        (BIO, Ptr{Cvoid}),
        bio_stream.bio,
        pointer_from_objref(bio_stream))
    return nothing
end

function bio_stream_from_data(bio::BIO)::BIOStream
    user_data::Ptr{Cvoid} = ccall(
        (:BIO_get_data, libcrypto),
        Ptr{Cvoid},
        (BIO,),
        bio)

    bio_stream::BIOStream = unsafe_pointer_to_objref(user_data)

    return bio_stream
end

Base.close(bio_stream::BIOStream) = free(bio_stream.bio)

"""
    SSLMethod.
    TLSv12ClientMethod.
"""
mutable struct SSLMethod
    ssl_method::Ptr{Cvoid}
end

function TLSv12ClientMethod()
    ssl_method = ccall(
        (:TLSv1_2_client_method, libssl),
        Ptr{Cvoid},
        ())
    if ssl_method == C_NULL
        throw(OpenSSLError())
    end

    return SSLMethod(ssl_method)
end

function TLSv12ServerMethod()
    ssl_method = ccall(
        (:TLSv1_2_server_method, libssl),
        Ptr{Cvoid},
        ())
    if ssl_method == C_NULL
        throw(OpenSSLError())
    end

    return SSLMethod(ssl_method)
end

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

        if !isempty(verify_file)
            ccall(
                (:SSL_CTX_load_verify_locations, libssl),
                Cint,
                (SSLContext, Ptr{Cchar}, Ptr{Cchar}),
                ssl_context,
                verify_file,
                C_NULL)
        end

        return ssl_context
    end
end

function free(ssl_context::SSLContext)
    ccall(
        (:SSL_CTX_free, libssl),
        Cvoid,
        (SSLContext,),
        ssl_context)

    ssl_context.ssl_ctx = C_NULL
    return nothing
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
    ccall(
        (:SSL_free, libssl),
        Cvoid,
        (SSL,),
        ssl)

    ssl.ssl = C_NULL
    return nothing
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
    if (ret = ccall(
        (:SSL_connect, libssl),
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

    # Clear ssl_error queue.
    ccall(
        (:ERR_clear_error, libcrypto),
        Cvoid,
        ())

    return nothing
end

function get_error(ssl::SSL, ret::Cint)::SSLErrorCode
    err = ccall(
        (:SSL_get_error, libssl),
        SSLErrorCode,
        (SSL, Cint),
        ssl,
        ret)
    @error err (OpenSSLError(err), catch_backtrace())
    err == SSL_ERROR_ZERO_RETURN && throw(ioerror())
    return err
end

ioerror() = Base.IOError("stream is closed or unusable", 0)

"""
    SSLStream.
"""
struct SSLStream <: IO
    ssl::SSL
    ssl_context::SSLContext
    bio_read_stream::BIOStream
    bio_write_stream::BIOStream
    lock::ReentrantLock

    function SSLStream(ssl_context::SSLContext, read_stream::IO, write_stream::IO)
        # Create a read and write BIOs.
        bio_read::BIO = BIO()
        bio_write::BIO = BIO()

        # Create a new BIOs instances (without the finalizer), as SSL will free them on close.
        bio_read_ssl_context = BIO(bio_read.bio)
        bio_write_ssl_context = BIO(bio_write.bio)

        bio_read_stream = BIOStream(bio_read_ssl_context, read_stream)
        bio_write_stream = BIOStream(bio_write_ssl_context, write_stream)

        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        ssl = SSL(ssl_context, bio_read_ssl_context, bio_write_ssl_context)

        # Ensure the finalization is no-op.
        bio_read.bio = C_NULL
        bio_write.bio = C_NULL

        return new(ssl, ssl_context, bio_read_stream, bio_write_stream, ReentrantLock())
    end
end

"""
    Force read operation on the stream. This will update the pending bytes.
"""
function force_read_buffer(ssl_stream::SSLStream)
    isclosed(ssl_stream) && return
    # If there is no data in the buffer, peek and force the first read.
    in_buffer = Ref{UInt8}()
    read_count = ccall(
        (:SSL_peek, libssl),
        Cint,
        (SSL, Ref{UInt8}, Cint),
        ssl_stream.ssl,
        in_buffer,
        1)
    if read_count <= 0
        throw(OpenSSLError(get_error(ssl_stream.ssl, read_count)))
    end
end

function Base.unsafe_write(ssl_stream::SSLStream, in_buffer::Ptr{UInt8}, in_length::UInt)
    isopen(ssl_stream) || throw(ArgumentError("unsafe_write requires ssl_stream to be open"))
    write_count::Int = 0
    write_count = ccall(
        (:SSL_write, libssl),
        Cint,
        (SSL, Ptr{Cvoid}, Cint),
        ssl_stream.ssl,
        in_buffer,
        in_length)
    if write_count <= 0
        throw(OpenSSLError(get_error(ssl_stream.ssl, write_count)))
    end

    return write_count
end

function Sockets.connect(ssl_stream::SSLStream)
    ssl_connect(ssl_stream.ssl)
end

hostname!(ssl::SSLStream, host) = ssl_set_host(ssl.ssl, host)

function Sockets.accept(ssl_stream::SSLStream)
    ssl_accept(ssl_stream.ssl)
end

"""
    Read from the SSL stream.
"""
function Base.unsafe_read(ssl_stream::SSLStream, buf::Ptr{UInt8}, nbytes::UInt)
    Base.@lock ssl_stream.lock begin
        nread = 0
        while nread < nbytes
            if eof(ssl_stream)
                throw(EOFError())
            end
            read_count = ccall(
                (:SSL_read, libssl),
                Cint,
                (SSL, Ptr{Int8}, Cint),
                ssl_stream.ssl,
                buf + nread,
                nbytes - nread)
            if read_count <= 0
                #TODO: should call SSL_get_error to see if retryable
                throw(OpenSSLError(get_error(ssl_stream.ssl, read_count)))
            end
            nread += read_count
        end
        return nread
    end
end

function Base.readavailable(ssl_stream::SSLStream)
    N = bytesavailable(ssl_stream)
    buf = Vector{UInt8}(undef, N)
    n = unsafe_read(ssl_stream, pointer(buf), N)
    return resize!(buf, n)
end

# function Base.readbytes!(s::SSLStream, b::AbstractArray{UInt8}, nb=length(b))
#     Base.require_one_based_indexing(b)
#     olb = lb = length(b)
#     nr = 0
#     while nr < nb && !eof(s)
#         nr += unsafe_read(s, pointer(b) + nr, lb - nr)
#         if nr == lb
#             lb = nr * 2
#             resize!(b, lb)
#         end
#     end
#     if lb > olb
#         resize!(b, nr) # shrink to just contain input data if was resized
#     end
#     return nr
# end

function Base.bytesavailable(ssl_stream::SSLStream)::Cint
    isclosed(ssl_stream) && return 0
    pending_count = ccall(
        (:SSL_pending, libssl),
        Cint,
        (SSL,),
        ssl_stream.ssl)
    update_tls_error_state()
    return pending_count
end

function haspending(s::SSLStream)
    isclosed(s) && return false
    has_pending = ccall(
        (:SSL_has_pending, libssl),
        Cint,
        (SSL,),
        s.ssl)
    update_tls_error_state()
    return has_pending == 1
end

function Base.eof(ssl_stream::SSLStream)::Bool
    isclosed(ssl_stream) && return true
    while bytesavailable(ssl_stream) <= 0
        # no immediate pending bytes, so let's check underlying socket
        if !haspending(ssl_stream) && eof(ssl_stream.bio_read_stream.io)
            return true
        end
        force_read_buffer(ssl_stream)
    end
    return false
end

Base.isreadable(ssl_stream::SSLStream)::Bool = !eof(ssl_stream) || isreadable(ssl_stream.bio_read_stream.io)
Base.iswritable(ssl_stream::SSLStream)::Bool = iswritable(ssl_stream.bio_write_stream.io)
Base.isopen(ssl_stream::SSLStream)::Bool = !isclosed(ssl_stream) && isopen(ssl_stream.bio_write_stream.io)
isclosed(ssl_stream::SSLStream) = ssl_stream.ssl.ssl == C_NULL

"""
    Close SSL stream.
"""
function Base.close(ssl_stream::SSLStream)
    isclosed(ssl_stream) && return
    # Ignore the disconnect result.
    ssl_disconnect(ssl_stream.ssl)

    # SSL_free() also calls the free()ing procedures for indirectly affected items, 
    # if applicable: the buffering BIO, the read and write BIOs, 
    # cipher lists specially created for this ssl, the SSL_SESSION.
    ssl_stream.bio_read_stream.bio.bio = C_NULL
    ssl_stream.bio_write_stream.bio.bio = C_NULL

    # close underlying read/write streams
    Base.close(ssl_stream.bio_read_stream.io)
    Base.close(ssl_stream.bio_write_stream.io)

    return finalize(ssl_stream.ssl)
end

"""
    Gets the X509 certificate of the peer.
"""
function get_peer_certificate(ssl_stream::SSLStream)::Option{X509Certificate}
    x509 = ccall(
        (:SSL_get_peer_certificate, libssl),
        Ptr{Cvoid},
        (SSL,),
        ssl_stream.ssl)
    if x509 != C_NULL
        return X509Certificate(x509)
    else
        return nothing
    end
end
