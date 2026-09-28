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

"""
    What the read and write BIOs of an `SSLStream` are given as their data.

OpenSSL calls the write BIO from inside `SSL_write_ex`, `SSL_connect`, `SSL_accept`
and `SSL_shutdown`, all of which run with `ssl.lock` held, and `SSL_read_ex` needs that
same lock. Writing to the socket in the callback therefore blocks every read on the
connection for as long as the peer's receive window stays full, which deadlocks any
traffic that saturates both directions at once. The callback only buffers; the task
that made the SSL call takes what it produced with `take!` while it still holds
`ssl.lock`, and moves it to the socket with `drain!` after releasing it.

Every SSL call runs under `ssl.lock` and takes its own output before releasing it, so
`buf` is empty whenever a call starts and only ever holds the records of the call in
progress: a reader never ends up writing a writer's ciphertext to the socket, and each
writer waits for its own bytes.
"""
mutable struct BIOStreamData
    io::TCPSocket
    # ciphertext produced by the SSL call in progress; only touched under `ssl.lock`,
    # both by the write BIO callback (OpenSSL runs it inside the SSL call) and by
    # `take!`
    buf::Vector{UInt8}
    # socket writes happen in the order the chunks were taken, so records leave in the
    # order OpenSSL made them: `take!` hands out a ticket and `drain!` waits for its
    # turn. Guards `nextticket`, `turn` and `abandoned`.
    cond::Threads.Condition
    nextticket::Int
    turn::Int
    # tickets whose task was cancelled while waiting for its turn; passed over when
    # the turn reaches them, so no ticket goes unconsumed and parks every later one
    abandoned::Set{Int}
    # tasks parked in `drain!` waiting for their turn
    waiting::Int
end

BIOStreamData(io::TCPSocket) = BIOStreamData(io, UInt8[], Threads.Condition(), 0, 0, Set{Int}(), 0)

"""
    Ciphertext one SSL call produced, and its place in the socket write order.
"""
struct PendingWrite
    chunk::Vector{UInt8}
    ticket::Int
end

"""
    take!(data::BIOStreamData) -> Union{PendingWrite, Nothing}

Takes the ciphertext the SSL call that just returned left in the write BIO. Must run
under `ssl.lock`, before it is released, so the chunk holds this task's records and
nothing another task produced afterwards. Returns `nothing` when the call produced no
output.
"""
function Base.take!(data::BIOStreamData)
    isempty(data.buf) && return nothing
    chunk = data.buf
    data.buf = UInt8[]
    ticket = Base.@lock data.cond begin
        t = data.nextticket
        data.nextticket += 1
        t
    end
    return PendingWrite(chunk, ticket)
end

"""
    Writes a chunk `take!` returned to the socket. Must be called without `ssl.lock`
    held. Chunks go out in ticket order, so a task whose records came after another
    task's waits for that task's socket write, and every task waits until its own bytes
    have reached the socket, or sees the error when they do not. Nothing to write costs
    nothing, so a reader never waits behind a writer that is blocked on the peer.

`owner`, when given, is the `SSLStream` the chunk belongs to: if it was closed while
this task waited for its turn, the chunk is not written and an `IOError` is thrown
instead. Records before it were lost, so sending it would only have the peer reject
it. The close paths pass no owner: the stream is closed by then by design.
"""
drain!(data::BIOStreamData, pending::Nothing, owner=nothing) = nothing
function drain!(data::BIOStreamData, pending::PendingWrite, owner=nothing)
    Base.@lock data.cond begin
        try
            while data.turn != pending.ticket
                data.waiting += 1
                try
                    wait(data.cond)
                finally
                    data.waiting -= 1
                end
            end
        catch
            # cancelled while waiting (`schedule(task, ex; error=true)`, an interrupt):
            # the ticket still has to be consumed, or the turn never gets past it and
            # every later writer parks on it. It may already be ours if the notification
            # and the cancellation raced. The record this chunk holds never reaches the
            # peer, which makes the connection unusable; `drain!(::SSLStream)` closes it,
            # so the writers still waiting fail on the socket instead of hanging.
            if data.turn == pending.ticket
                passturn!(data)
            else
                push!(data.abandoned, pending.ticket)
            end
            rethrow()
        end
    end
    try
        owner === nothing || isopen(owner) || throw(Base.IOError("ssl is closed", 0))
        chunk = pending.chunk
        GC.@preserve chunk unsafe_write(data.io, pointer(chunk), UInt(length(chunk)))
    finally
        # always pass the turn on, or one failed write would park every later one
        Base.@lock data.cond passturn!(data)
    end
    return nothing
end

# hands the turn to the next ticket that still has a task waiting for it; under `cond`
function passturn!(data::BIOStreamData)
    data.turn += 1
    while data.turn in data.abandoned
        delete!(data.abandoned, data.turn)
        data.turn += 1
    end
    notify(data.cond)
    return nothing
end

function on_bio_stream_read(bio::BIO, out::Ptr{Cchar}, outlen::Cint)
    try
        bio_clear_flags(bio)
        data = bio_get_data(bio)
        io = data isa BIOStreamData ? data.io : data::IO
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
        data = bio_get_data(bio)
        if data isa BIOStreamData
            # buffer only; the caller of the SSL call this runs inside takes it with
            # `take!` and writes it to the socket with `drain!` once `ssl.lock` is free
            n = length(data.buf)
            resize!(data.buf, n + inlen)
            GC.@preserve data unsafe_copyto!(pointer(data.buf, n + 1), Ptr{UInt8}(in), UInt(inlen))
            return inlen
        end
        written = unsafe_write(data::IO, in, inlen)
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

# Use NetworkOptions for default CA file so that it can be configured using the standard
# environment variables (JULIA_SSL_CA_ROOTS_PATH, SSL_CERT_DIR, and SSL_CERT_FILE).
# TODO: On Windows and macOS `ca_roots` return `nothing` to indicate that system configured
#       certificates should be preferred but for now we fall back to the certificate from
#       MozillaCACerts_jll.
default_cacert() = something(NetworkOptions.ca_roots(), MozillaCACerts_jll.cacert)

"""
    This is the global context structure which is created by a server or client once per program life-time
    and which holds mainly default values for the SSL structures which are later created for the connections.
"""
mutable struct SSLContext
    ssl_ctx::Ptr{Cvoid}

    function SSLContext(ssl_method::SSLMethod, verify_file::String = default_cacert())
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
            ret = ca_chain!(ssl_context, verify_file)
            if ret != 1
                error("Failed to validate CA certificates at '$(verify_file)'.")
            end
        end

        return ssl_context
    end
end

function ca_chain!(ssl_context::SSLContext, cacert::String)

    if isfile(cacert)
        ccall(
            (:SSL_CTX_load_verify_locations, libssl),
            Cint,
            (SSLContext, Ptr{Cchar}, Ptr{Cchar}),
            ssl_context,
            cacert,
            C_NULL)
    elseif isdir(cacert)
        ccall(
            (:SSL_CTX_load_verify_locations, libssl),
            Cint,
            (SSLContext, Ptr{Cchar}, Ptr{Cchar}),
            ssl_context,
            C_NULL,
            cacert)
    else
        ArgumentError("Invalid CA certificates location: $cacert")
    end

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
    closed::Bool
    # buffers the ciphertext the BIO callbacks produce, see `BIOStreamData`
    data::BIOStreamData

    function SSLStream(ssl_context::SSLContext, io::TCPSocket)
        # Create a read and write BIOs.
        data = BIOStreamData(io)
        bio_read::BIO = BIO(data; finalize=false)
        bio_write::BIO = BIO(data; finalize=false)
        ssl = SSL(ssl_context, bio_read, bio_write)
        x = new(ssl, ssl_context, bio_read, bio_write, io, ReentrantLock(), ReentrantLock(), false, data)
        # no close_notify from the finalizer: sending it is a socket write, which can
        # wait for the peer, and a finalizer may not switch tasks
        finalizer(x -> close(x, false), x)
        return x
    end
end

SSLStream(tcp::TCPSocket) = SSLStream(SSLContext(OpenSSL.TLSClientMethod()), tcp)

# backwards compat
Base.getproperty(ssl::SSLStream, nm::Symbol) = nm === :bio_read_stream ? ssl : getfield(ssl, nm)

function drain!(ssl::SSLStream, pending)
    try
        drain!(getfield(ssl, :data), pending, ssl)
    catch
        # a failed socket write used to surface through the BIO callback as an SSL
        # error, which closed the stream; keep that so `isopen` does not report a
        # connection whose ciphertext never reached the peer as usable
        close(ssl, false)
        rethrow()
    end
end

Base.isreadable(ssl::SSLStream)::Bool = isopen(ssl) && isreadable(ssl.io)
Base.isopen(ssl::SSLStream)::Bool = Base.@lock(ssl.lock, !ssl.closed)
Base.iswritable(ssl::SSLStream)::Bool = isopen(ssl) && isopen(ssl.io)
@noinline throwio(op) = throw(Base.IOError("$op requires ssl to be open", 0))

# this is a macro, but should be a function, but closures are stupid slow
# we use this to standardize the error handling for all of the SSL_*_ex functions:
# make the ccall under `ssl.lock`, check the error queue, and take the ciphertext the
# call produced while still holding the lock. Evaluates to `(ret, pending, err)`, for
# `finish_sslcall!` once every lock that must not be held across the socket write is
# released; `@geterror` is the two together.
macro sslcall(ssl, op, expr)
    esc(quote
        local _err = nothing
        local _ret = SSL_ERROR_NONE
        local _pending = Base.@lock $ssl.lock begin
            # check that SSL is still open before ccall
            $ssl.closed && throwio($op)
            # clear the current error queue before openssl ccall
            clear_errors!()
            # do the ccall
            _r = $expr
            # we want to return one of our SSL return codes, regardless of error
            # SSL_peek_ex, SSL_write_ex, SSL_connect, SSL_accept and SSL_read_ex all
            # return 1 on success
            if _r != 1
                _e = get_error($ssl.ssl, _r)
                if _e == SSL_ERROR_ZERO_RETURN
                    # the peer sent a close_notify, so no more reading is possible
                    _err = Base.IOError("unexpected EOF", 0)
                elseif _e == SSL_ERROR_NONE || _e == SSL_ERROR_WANT_READ || _e == SSL_ERROR_WANT_WRITE
                    # WANT_READ: we need to read more data from the underlying socket
                    # WANT_WRITE: we need to write more data to the underlying socket;
                    # we don't expect to ever see this since we set up our SSL
                    # to do auto TLS (re)negotiation
                    _ret = _e
                else
                    # this is usually some other kind of error, like a protocol error
                    # or OS-level IO error, just close the SSL connection and throw
                    # notably, the openssl docs say we should *not* call ssl_disconnect
                    # in this case, hence the `false` arg to close
                    _err = Base.IOError(OpenSSLError(_e).msg, 0)
                end
            end
            if _err === nothing
                take!(getfield($ssl, :data))
            else
                # close under the lock we already hold; what comes back is the alert
                # OpenSSL queued for the peer, sent by `finish_sslcall!` once the lock
                # is released
                closelocked!($ssl, false)
            end
        end
        (_ret, _pending, _err)
    end)
end

# the second half of an SSL call: send the alert and throw when it failed, otherwise
# write what it produced to the socket and hand back its return code. The write BIO
# only buffers, so this is where the socket write happens, and the caller waits for the
# peer here rather than under `ssl.lock`.
function finish_sslcall!(ssl::SSLStream, ret::SSLErrorCode, pending, err)
    if err !== nothing
        closesocket!(ssl, pending)
        throw(err)
    end
    drain!(ssl, pending)
    return ret
end

macro geterror(ssl, op, expr)
    esc(:(finish_sslcall!($ssl, (@sslcall $ssl $op $expr)...)))
end

# the write BIO buffers the whole output of one `SSL_write_ex` before `drain!` moves it
# to the socket, so cap how much plaintext goes into a single call to bound that buffer
const SSL_WRITE_CHUNK = UInt(1 << 20)

function Base.unsafe_write(ssl::SSLStream, in_buffer::Ptr{UInt8}, in_length::UInt)
    nwritten = 0
    # per call, not per stream: `@geterror` writes to the socket after releasing
    # `ssl.lock`, and another task's `SSL_write_ex` would overwrite a shared count
    # before it is read back below
    writebytes = Ref{Csize_t}(0)
    while nwritten < in_length
        # SSL_write_ex writes all or nothing without SSL_MODE_ENABLE_PARTIAL_WRITE, so a
        # retry after WANT_READ/WANT_WRITE resubmits the same chunk
        chunk = min(in_length - nwritten, SSL_WRITE_CHUNK)
        ret = @geterror ssl :unsafe_write ccall(
            (:SSL_write_ex, libssl),
            Cint,
            (SSL, Ptr{Cvoid}, Csize_t, Ptr{Csize_t}),
            ssl.ssl,
            in_buffer + nwritten,
            chunk,
            writebytes
        )
        if ret == SSL_ERROR_NONE
            nwritten += writebytes[]
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
    while true
        ret = @geterror ssl :accept ccall(
            (:SSL_accept, libssl),
            Cint,
            (SSL,),
            ssl.ssl)
        if ret == SSL_ERROR_NONE
            break
        elseif ret == SSL_ERROR_WANT_READ
            # this means accept is waiting for more data from the underlying socket
            # so call eof on the socket to wait for more bytes to come in
            eof(ssl.io) && throw(EOFError())
        else
            throw(Base.IOError(OpenSSLError(ret).msg, 0))
        end
    end

    # see `connect`
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

"""
    Read from the SSL stream.
"""
function Base.unsafe_read(ssl::SSLStream, buf::Ptr{UInt8}, nbytes::UInt)
    nread = 0
    # per call, see `unsafe_write`
    readbytes = Ref{Csize_t}(0)
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
    # per call, see `unsafe_write`
    peekbuf = Ref{UInt8}(0x00)
    peekbytes = Ref{Csize_t}(0)
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
            ret, pending, err = @sslcall ssl :peek ccall(
                (:SSL_peek_ex, libssl),
                Cint,
                (SSL, Ptr{UInt8}, Cint, Ptr{Csize_t}),
                ssl.ssl,
                peekbuf,
                1,
                peekbytes
            )
            if pending === nothing && err === nothing
                if ret == SSL_ERROR_NONE
                    return false
                elseif ret == SSL_ERROR_WANT_WRITE
                    flush(ssl.io)
                elseif ret == SSL_ERROR_WANT_READ
                    # if we get WANT_READ back, that means there were pending bytes
                    # to be processed, but not a full record, so we need to wait
                    # for additional bytes to come in before we can process. If the
                    # socket is at EOF they never will: the peer went away mid-record,
                    # so this is the end of the stream. Looping instead would spin,
                    # `haspending` stays true for the partial record and `eof(ssl.io)`
                    # returns at once, without ever yielding.
                    eof(ssl.io) && return true
                end
                continue
            end
            (ret, pending, err)
        end
        # processing the record produced something for the peer (a KeyUpdate reply, or
        # the alert of a record that failed): send it, or fail, without holding
        # `eoflock`. A writer parked on a peer that is not reading would otherwise hold
        # every other reader up through this lock. Then go round again: whether the
        # peek made bytes available is re-checked at the top.
        finish_sslcall!(ssl, ret, pending, err)
    end
    bytesavailable(ssl) > 0 && return false
    return !isopen(ssl)
end

"""
    Close SSL stream.
"""
function Base.close(ssl::SSLStream, shutdown::Bool=true)
    pending = Base.@lock ssl.lock begin
        ssl.closed && return
        closelocked!(ssl, shutdown)
    end
    closesocket!(ssl, pending)
end

# marks the stream closed and frees the SSL object; must run under `ssl.lock`, which
# the caller keeps holding. Returns what OpenSSL left in the write BIO, the close_notify
# when `shutdown` is set or the fatal alert of the call that failed, for `closesocket!`
# to send once the lock is released.
function closelocked!(ssl::SSLStream, shutdown::Bool)
    if !ssl.closed
        ssl.closed = true
        if shutdown
            try
                ssl_disconnect(ssl.ssl)
            catch err
                @debug "SSL disconnect failed" err
            end
        end
        free(ssl.ssl)
    end
    return take!(getfield(ssl, :data))
end

# sends what `closelocked!` returned, best effort, then closes the socket. Must be
# called without `ssl.lock` held: the peer may not be reading.
function closesocket!(ssl::SSLStream, pending)
    try
        drain!(getfield(ssl, :data), pending)
    catch err
        # the peer being gone is expected here; an interrupt or a cancellation of the
        # task is not ours to swallow
        err isa Union{Base.IOError, EOFError} || rethrow()
        @debug "SSL alert not sent" err
    finally
        @async try
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
