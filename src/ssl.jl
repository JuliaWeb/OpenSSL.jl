# a log call on a cleanup path: nothing a logger throws (one that does not catch its own
# errors rethrows them) is taken for the cleanup's failure, nor stops what the cleanup
# does after it
macro guarded(ex)
    return quote
        try
            $(esc(ex))
        catch
        end
        nothing
    end
end

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
    Ciphertext one SSL call produced, and its place in the socket write order.
"""
struct PendingWrite
    chunk::Vector{UInt8}
    ticket::Int
end

"""
    What the read and write BIOs of an `SSLStream` are given as their data.

OpenSSL calls the write BIO from inside `SSL_write_ex`, `SSL_connect`, `SSL_accept`
and `SSL_shutdown`, and from `SSL_read_ex` and `SSL_peek_ex` too when a read produces
records of its own (a reply to a KeyUpdate, an alert), all of which run with `ssl.lock`
held. Writing to the socket in the callback therefore blocks every read on the
connection for as long as the peer's receive window stays full, which deadlocks any
traffic that saturates both directions at once. The callback only buffers; the task
that made the SSL call takes what it produced with `take!` while it still holds
`ssl.lock`, and moves it to the socket with `drain!` after releasing it. Some sends are
not the caller's: a read's reply goes out from a task of its own (see
`finish_sslcall!`), the alert of a call that failed goes out with the abort (see
`abortlocked!`), and the close_notify of a dropped stream whose socket outlived it goes
out from the finalizer's task (see `finalize!`).

Every SSL call runs under `ssl.lock` and takes its own output before releasing it, so
`buf` is empty whenever a call starts (a close cut short between producing its
close_notify and taking it leaves it there, for the abort that follows to empty) and
only ever holds the records of the call in progress: a reader never ends up writing a
writer's ciphertext to the socket, and each writer waits for its own bytes; and a
reader, its reply sent from a task of its own, never waits behind a writer either.
"""
mutable struct BIOStreamData
    io::TCPSocket
    # ciphertext produced by the SSL call in progress; only touched under `ssl.lock`,
    # both by the write BIO callback (OpenSSL runs it inside the SSL call) and by
    # `take!`
    buf::Vector{UInt8}
    # socket writes happen in the order the chunks were taken, so records leave in the
    # order OpenSSL made them: `take!` hands out a ticket and `drain!` waits for its
    # turn. Guards `turn`, `abandoned`, `waiting`, `lostfrom` and `cut`.
    cond::Threads.Condition
    # the next ticket: handed out only by `take!`, under `ssl.lock`, which serialises
    # every SSL call, and read there, or once an abort has marked the stream closed,
    # after which no call makes records nor takes a ticket
    nextticket::Int
    turn::Int
    # tickets given up before the turn reached them (their task cancelled while it
    # waited, refused for a loss before them, or an abort's alert given up); passed over
    # when the turn reaches them, so no ticket goes unconsumed and parks every later one
    abandoned::Set{Int}
    # tasks parked in `drain!` waiting for their turn
    waiting::Int
    # the first ticket whose record did not reach the socket: its task was cancelled,
    # its write failed, or the socket was cut (see `cut!`). Nothing from that ticket on
    # may be sent, the peer would reject it at the gap in the sequence numbers, and
    # that includes the close_notify: the stream can only be aborted. `typemax(Int)`
    # until then.
    lostfrom::Int
    # an abort is under way (see `abortlocked!`); a second one has nothing to add. Set
    # and read under `ssl.lock`, where every abort runs
    aborted::Bool
    # a graceful close sent its close_notify and handed the socket to its normal close:
    # the finalizer has nothing to finish
    handedoff::Bool
    # the socket handle was closed outright (see `cut!`): no ticket is written any more,
    # and whatever waits for one stops waiting. Under `cond`
    cut::Bool
    # a chunk that reached the socket, emptied, for `take!` to hand the write BIO as its
    # next buffer instead of growing a new one record by record. Only a sent chunk: libuv
    # is done with it then, and nothing else holds it. Under `cond`
    spare::Union{Nothing, Vector{UInt8}}
end

BIOStreamData(io::TCPSocket) = BIOStreamData(io, UInt8[], Threads.Condition(), 0, 0, Set{Int}(), 0, typemax(Int), false, false, false, nothing)

"""
    take!(data::BIOStreamData) -> Union{PendingWrite, Nothing}

Takes the ciphertext the SSL call that just returned left in the write BIO. Must run
under `ssl.lock`, before it is released, so the chunk holds this task's records and
nothing another task produced afterwards. Returns `nothing` when the call produced no
output.
"""
function Base.take!(data::BIOStreamData)
    isempty(data.buf) && return nothing
    # the buffer that takes over made first; then the ticket and the swap, together and
    # with no wait, no call and no allocation among them, so nothing can land in
    # between: no lock either, `ssl.lock` serialising the tickets (see `nextticket`).
    # An interrupt at the allocation leaves the records where they are, for `@sslcall`
    # to give up together with the stream
    fresh = takespare!(data)
    ticket = data.nextticket
    data.nextticket = ticket + 1
    chunk = data.buf
    data.buf = fresh
    return PendingWrite(chunk, ticket)
end

# the spare chunk (see `spare`), or a new buffer when there is none or `cond` is held:
# `take!` runs under `ssl.lock` and must not wait for a writer
function takespare!(data::BIOStreamData)
    spare = nothing
    if trylock(data.cond)
        try
            spare = data.spare
            data.spare = nothing
        finally
            unlock(data.cond)
        end
    end
    return spare === nothing ? UInt8[] : spare
end

# keeps a chunk that reached the socket as the spare (see `spare`), unless there is one
# already or it is larger than one record of a write (a handshake flight, say), which
# would hold that memory for as long as the stream lives; under `cond`
function keepspare!(data::BIOStreamData, chunk::Vector{UInt8})
    if data.spare === nothing && length(chunk) <= SPARE_MAX
        empty!(chunk)
        data.spare = chunk
    end
    return nothing
end

"""
    Writes a chunk `take!` returned to the socket. Must be called without `ssl.lock`
    held. Chunks go out in ticket order, so a task whose records came after another
    task's waits for that task's socket write, and every task waits until its own bytes
    have reached the socket, or sees the error when they do not. Nothing to write costs
    nothing, so a reader never waits behind a writer that is blocked on the peer.

Once a record was lost (see `lostfrom`), the chunks after it are refused with an
`IOError` instead of being written.
"""
drain!(data::BIOStreamData, pending::Nothing) = nothing
function drain!(data::BIOStreamData, pending::PendingWrite)
    try
        Base.@lock data.cond begin
            while true
                # refused (see `lostfrom`), whether before or once the turn is here
                pending.ticket >= data.lostfrom && throw(Base.IOError("an earlier record was not sent", 0))
                data.turn == pending.ticket && break
                data.waiting += 1
                try
                    wait(data.cond)
                finally
                    data.waiting -= 1
                end
            end
        end
    catch
        # refused, or cancelled (`schedule(task, ex; error=true)`, an interrupt) while
        # taking the lock or waiting for the turn: the ticket still has to be consumed,
        # or the turn never gets past it and every later writer parks on it. With an
        # interrupt held back: taking the lock is a cancellation point where there are
        # such, and a cancelled task would otherwise be stopped short of it
        holdinterrupts(() -> abandon!(data, pending.ticket))
        rethrow()
    end
    sent = false
    # the write ended with libuv's own error status for it (the `IOError` Base makes of
    # it, "write: ..." with the libuv code, which is negative): libuv finished the request,
    # and holds no pointer into the chunk. Anything else ending it (a cancellation, any
    # other exception thrown into the task, an interrupt, or this never being set) may
    # leave the write queued. The message is Base's wording: were it ever reworded,
    # failed writes would keep their chunks until their sockets close, a leak and no
    # more, and `FailedWriteKeepsNothing` would say so
    finished = false
    failure = nothing
    try
        write(data.io, pending.chunk)
        sent = true
    catch ex
        failure = ex
        finished = ex isa Base.IOError && ex.code < 0 && startswith(ex.msg, "write:")
        rethrow()
    finally
        # bound anew for the closures: captured as they are, having been assigned in the
        # `try`, they would be boxed on every write
        let sent = sent, ticket = pending.ticket, keep = finished ? nothing : pending.chunk,
                failure = failure, chunk = pending.chunk
            # The write failed, or the task was cancelled inside it. The record is lost
            # either way, and with it the stream. A cancelled write is moreover still
            # queued in libuv, with a pointer into the chunk that nothing keeps alive any
            # more: closing the socket handle now cancels it, and the chunk is kept until
            # it has. (A cancellation that lands just as the write completed replaces its
            # result, so that record is counted lost, and the stream given up, though it
            # got through: the conservative side of not being able to tell.) Here in the
            # `finally` rather than in the `catch`, which a second interrupt could leave
            # before it got this far; one landing on the very entry of the `finally` is as
            # close as Julia lets this be shut, and is Base's own `uv_write` gap, the
            # interrupted write's buffer left to its caller.
            #
            # And the turn is always passed on, or one failed write would park every later
            # one: in the same hold as the cut, so that an interrupt held back during the
            # cut, thrown as a hold ends, cannot come between them, and whatever the cut
            # throws (an interrupt, or an exception thrown into the task; a failure it
            # logs itself, with the write's error)
            holdinterrupts() do
                try
                    sent || cut!(data, keep, failure)
                finally
                    passon!(data, ticket, sent, chunk)
                end
            end
        end
    end
    return nothing
end

# closes the socket handle outright, and ends whatever waits for a turn or for every
# ticket to be through; with an interrupt held back, so that both happen. Every close
# of the handle outright goes through this: a failed write, the handshake deadline, a
# watch giving up, an abort that failed. The close failing is logged, with `cause`, what
# the cut is for, if given (not the whole exception stack: on a caller's task that holds
# the caller's own errors too). What comes out is an interrupt, or an exception thrown
# into the task (see `surely`)
function cut!(data::BIOStreamData, keep=nothing, cause=nothing)
    holdinterrupts() do
        try
            forceclose!(data.io, keep)
        catch ex
            # nothing in the close throws one, and the hold keeps a Ctrl-C off; should
            # one come all the same, where a hold cannot keep it off, it is the task's
            ex isa InterruptException && rethrow()
            bt = catch_backtrace()
            @guarded @error("OpenSSL: closing a socket outright failed",
                exception=(ex, bt), cause)
        finally
            # recorded in the ticket state, not left to the socket's status, which a
            # fallback close sets only later and without a word to these waiters: every
            # ticket from the turn on is refused, which ends the turn waits, and `cut`
            # ends the abort's wait for tickets to come through, a ticket never drained
            # included. Whatever the close did
            surely(data.cond) do
                data.cut = true
                lose!(data, data.turn)
            end
        end
    end
    return nothing
end

# passes the turn on after a drain; a chunk not sent is given up as `abandon!` does
function passon!(data::BIOStreamData, ticket::Int, sent::Bool, chunk::Vector{UInt8})
    sent || return abandon!(data, ticket)
    surely(data.cond) do
        passturn!(data)
        keepspare!(data, chunk)
    end
    return nothing
end

# records that the chunk of `ticket` is not going to be sent, and wakes the tasks waiting
# for their turn so those now refused can leave; under `cond`
function lose!(data::BIOStreamData, ticket::Int)
    data.lostfrom = min(data.lostfrom, ticket)
    notify(data.cond)
    return nothing
end

# gives up on a ticket whose chunk will never be written. Consumes the ticket, right
# away when the turn is already on it, otherwise when the turn reaches it; and records
# the loss. Takes `cond` itself, `abandon!` may run after a cancelled `lock`; surely, as
# every cleanup takes its locks (see `surely`).
function abandon!(data::BIOStreamData, ticket::Int)
    surely(data.cond) do
        lose!(data, ticket)
        if data.turn == ticket
            passturn!(data)
        else
            push!(data.abandoned, ticket)
        end
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

# every ticket handed out is through, drained or given up; under `cond`, and on a stream
# marked closed, `nextticket` being otherwise `take!`'s, under `ssl.lock`
drained(data::BIOStreamData) = data.turn == data.nextticket

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
            buf = data.buf
            n = length(buf)
            resize!(buf, n + inlen)
            GC.@preserve buf unsafe_copyto!(pointer(buf, n + 1), Ptr{UInt8}(in), Int(inlen))
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

# one round of the client side of the handshake. Internal: with the write BIO
# buffering, what it produces stays in the stream's buffer, for `@geterror` around it to
# take under `ssl.lock` and send after; `Sockets.connect(::SSLStream)` is the way to
# connect
function ssl_connect(ssl::SSL)
    return ccall(
        (:SSL_connect, libssl),
        Cint,
        (SSL,),
        ssl)
end

# gone in 1.6.2: with the write BIO buffering, its handshake output never reached the
# socket, and working on the bare handle it had no way to send it
ssl_accept(::SSL) = error("ssl_accept was removed: use Sockets.accept(::SSLStream)")

# queues the close_notify. Internal, as `ssl_connect`: `close(::SSLStream)` is the way
# to shut a stream down
function ssl_disconnect(ssl::SSL)
    ret = ccall(
        (:SSL_shutdown, libssl),
        Cint,
        (SSL,),
        ssl)
    # a failure only reports, on the thread's error queue, where a later call would
    # take it for its own
    ret < 0 && clear_errors!()
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
    # held for the whole of a `write`: it goes to OpenSSL in chunks, with `lock` released
    # between them, and the chunks of two writers must not interleave
    wlock::ReentrantLock
    closed::Bool
    # the writes in flight, and whether a graceful close has begun, in one word: the
    # `CLOSING` bit and a count. A write counts itself in with a compare-and-swap that
    # fails once the bit is set, so a write issued before the close is counted and goes
    # through, whichever gets `wlock` first, and one issued after is refused at once
    # without ever being counted: neither a writer in a loop, retrying or not, nor a
    # parked one keeps the close waiting for good. The close sets the bit and waits on
    # `closecond`, on `lock`, for the count to reach zero; a second close finds the bit
    # set and returns. Should a count be left standing all the same, nothing moves, and
    # the close's watch gives up and ends the wait
    wstate::Threads.Atomic{Int}
    closecond::Threads.Condition
    # buffers the ciphertext the BIO callbacks produce, see `BIOStreamData`
    data::BIOStreamData
    # scratch for `SSL_peek_ex` in `eof`: written by the call, never read back, so one
    # per stream is fine (the read count has to be per call, and the write count is, see
    # `unsafe_read` and `unsafe_write`)
    peekbuf::Base.RefValue{UInt8}
    peekbytes::Base.RefValue{Csize_t}

    function SSLStream(ssl_context::SSLContext, io::TCPSocket)
        # Create a read and write BIOs.
        data = BIOStreamData(io)
        bio_read::BIO = BIO(data; finalize=false)
        bio_write::BIO = BIO(data; finalize=false)
        ssl = SSL(ssl_context, bio_read, bio_write)
        lk = ReentrantLock()
        x = new(ssl, ssl_context, bio_read, bio_write, io, ReentrantLock(), lk,
            ReentrantLock(), false, Threads.Atomic{Int}(0), Threads.Condition(lk),
            data, Ref{UInt8}(0x00), Ref{Csize_t}(0))
        finalizer(finalize!, x)
        return x
    end
end

SSLStream(tcp::TCPSocket) = SSLStream(SSLContext(OpenSSL.TLSClientMethod()), tcp)

# `shielded` runs `f` out of reach of a cancellation of the caller's scope, where there
# is such a thing (from the Julia nightly on, an interrupt is one): tasks made in there do
# not inherit it, as Base does for its own. `holdinterrupts` runs `f` with an
# interrupt held back: the same there, where `disable_sigint` no longer holds one back
# (it warns instead), and `disable_sigint` elsewhere
@static if isdefined(Base, :CANCEL_TOKEN)
    shielded(f) = Base.ScopedValues.with(f, Base.CANCEL_TOKEN => nothing)
    holdinterrupts(f) = shielded(f)
else
    shielded(f) = f()
    holdinterrupts(f) = disable_sigint(f)
end

# runs `f` in a task of its own. Not `@async`: from Julia 1.7 that pins the task that
# calls it to its thread for good, and these are called from readers and writers that
# may well have been spawned themselves. In the caller's thread pool, so that an
# interactive task's cleanup does not queue behind compute work. (The finalizer's
# `@async` is not pinned: a finalizer runs on no task of its own.)
@static if isdefined(Threads, :threadpool)
    # a task made as `Threads.@spawn` makes it, not yet scheduled, for what must exist
    # before anything is changed that it is to finish
    function unscheduled(f)
        pool = Threads.threadpool() === :interactive ? :interactive : :default
        return shielded() do
            task = Task(f)
            task.sticky = false
            Threads._spawn_set_thrpool(task, pool)
            task
        end
    end
else
    function unscheduled(f)
        task = Task(f)
        task.sticky = false
        return task
    end
end
background(f) = schedule(unscheduled(f))

# `f()` under `l`, for the cleanup sections, which have to get through; then `then`, if
# given, on its value, outside the lock. The wait for the lock is where an exception
# thrown into the task (`schedule(task, ex; error=true)`, which an interrupt hold does
# not keep off, as it does a Ctrl-C) can still land: then the section, and `then`, are
# left to a task of the library's, which nothing outside it can throw into, and the
# exception goes on at once. Returns what `then` returns, or the section's value
function surely(f, l; then=nothing)
    try
        lock(l)
    catch
        leave() do
            local v = Base.@lock(l, f())
            then === nothing ? v : then(v)
        end
        rethrow()
    end
    r = try
        f()
    finally
        unlock(l)
    end
    return then === nothing ? r : then(r)
end

# runs `f` on a task of the library's, which nothing waits for, whole (see `runwhole`),
# a failure logged. Returns the task
leave(f) = background() do
    try
        runwhole(f)
    catch ex
        if ex isa InterruptException
            # one `f` threw itself, the only kind `runwhole` passes on
            @guarded @error "OpenSSL: a cleanup left to a task of the library was interrupted" exception=caught(ex)
        else
            @guarded @error "OpenSSL: a cleanup left to a task of the library failed" exception=caught(ex)
        end
    end
end

# runs `f` whole, on a task of the library's, which nothing can throw into but a Ctrl-C:
# with an interrupt held back. One that lands before the hold began has `f` run as if it
# had not; one thrown as the hold ends, `f` done by then, is said to be lost. What `f`
# throws itself is thrown
function runwhole(f)
    # 0 before the hold, 1 in `f`, 2 once `f` is done; made once, before the loop, so that
    # a rerun (only ever from 0) sets nothing up outside the `try`
    phase = Ref(0)
    result = Ref{Any}(nothing)
    while true
        try
            holdinterrupts() do
                phase[] = 1
                result[] = f()
                phase[] = 2
            end
            return result[]
        catch ex
            if ex isa InterruptException
                phase[] == 0 && continue
                phase[] == 2 && (lostinterrupt(); return result[])
            end
            rethrow()
        end
    end
end

# `f()` on a task of the library's, through interrupts, for a step that can be run again
# and may wait with no bound (a close, a wait for a condition), so not in a hold: one
# landing in it is said to be lost, and `f` run again
function through(f)
    while true
        try
            return f()
        catch ex
            ex isa InterruptException || rethrow()
            lostinterrupt()
        end
    end
end

# a timer that calls `cb(timer)` on each tick, as `Timer(cb, delay; interval)` does, from
# a task made with `background`: the task `Timer(cb, ...)` makes pins, up to Julia 1.11,
# the task that creates the timer to its thread. (A timer with no callback carries no
# cancellation scope: what it is waited on in decides, and `background` shields that
# task.) Closing the timer ends it; a one-shot timer closes itself once it has gone off.
#
# Each callback runs with interrupts held back, so that it is not stopped half way; the
# waits do not, since a hold there would keep Ctrl-C from the whole process while it
# idles on this task. An interrupt, wherever else it lands, is not meant for the timer:
# it is said to have been lost and the timer goes on, or a watch would stop and leave a
# parked writer unfailed. What becomes of a tick it cut short depends on the timer. A
# one-shot timer's callback runs again, and runs once the timer can no longer go off
# should the interrupt have hidden that it did: a one-shot callback must be safe to run
# after its owner closed the timer and again after it was cut short (the handshake
# deadline's is). A repeating timer's tick is dropped and the next one waited for: a
# watch run again at once would judge nothing to have moved in no time. An error in a
# callback is logged and ends the timer, closed
function ticker(cb, delay::Real; interval::Real=0)
    timer = Timer(delay; interval=interval)
    background() do
        # :idle, waiting for a tick; :due, a tick the callback has yet to run to its end
        # for; :done, a one-shot timer's callback ran; :failed, a callback failed. Set
        # within the callback's hold where it is the callback's outcome, so that an
        # interrupt held back meanwhile, thrown as the hold ends, cannot keep it unset
        state = Ref(:idle)
        interrupted = false
        try
            while true
                try
                    if interrupted
                        interrupted = false
                        lostinterrupt()
                        if interval == 0
                            # a one-shot timer that can no longer go off may have gone
                            # off unseen, the interrupt landing in the wait as it did
                            state[] === :idle && !isopen(timer) && (state[] = :due)
                        else
                            state[] === :due && (state[] = :idle)
                        end
                    end
                    tickloop(cb, timer, interval, state)
                    return
                catch ex
                    # only noted here, handled at the top of the next round: little
                    # enough happens in a `catch` for another interrupt to land in it
                    ex isa InterruptException || rethrow()
                    interrupted = true
                end
            end
        catch ex
            @guarded @error "OpenSSL: timer failed" exception=caught(ex)
        finally
            close(timer)
        end
    end
    return timer
end

# the ticks, until the timer is done with. Every way out is checked at the top of each
# round, where an interrupt that came in anywhere cannot have skipped it
function tickloop(cb, timer::Timer, interval::Real, state)
    while true
        state[] in (:failed, :done) && return
        # a repeating timer closed by its owner is done with, whatever tick raced the
        # close (`wait` still returns for a tick set before it)
        interval == 0 || isopen(timer) || return
        if state[] === :idle
            open = try
                wait(timer)
                true
            catch ex
                ex isa EOFError || rethrow()
                false
            end
            if open && (interval == 0 || isopen(timer))
                state[] = :due
            elseif open
                return
            else
                # closed: by its owner, or by itself as a one-shot timer that went off.
                # Up to Julia 1.13 a first wait that meets the going off can see the timer
                # closed without seeing it set; a tick that happened is not lost. Only
                # for a one-shot timer: a repeating one closed by its owner is done with,
                # whatever tick raced the close
                interval == 0 && timerfired(timer) && (state[] = :due)
                state[] === :due || return
            end
        end
        runheld(cb, timer, interval, state)
    end
end

# what a `catch` in the ticker's own task logs of `ex`, the exception it is handling: the
# task's whole exception stack where Julia keeps it (1.7 on), so that an error thrown in
# a `finally` while another was on its way shows that one as its cause. Only there: on
# a caller's task the stack holds whatever the caller's own code is handling, which is
# no cause of the library's error
caught(ex) = @static VERSION >= v"1.7" ? current_exceptions() : (ex, catch_backtrace())

# one callback, held against interrupts, its outcome recorded within the hold. An
# interrupt out of the callback itself leaves the tick due, for `ticker` to decide on
function runheld(cb, timer::Timer, interval::Real, state)
    holdinterrupts() do
        try
            cb(timer)
            state[] = interval == 0 ? :done : :idle
        catch ex
            ex isa InterruptException && rethrow()
            @guarded @error "OpenSSL: timer callback failed" exception=caught(ex)
            state[] = :failed
        end
    end
    return nothing
end

# says that an interrupt landed in a task of the library and was not passed on; with
# further interrupts held back while it does, and those, as anything a logger throws,
# swallowed after
function lostinterrupt()
    @guarded holdinterrupts() do
        @warn "OpenSSL: an interrupt landed in a task of the library and was not passed on (nor any that came while this was said)"
    end
    return
end

# `set` became an atomic field during Julia 1.8's development, a plain one before, and
# no version number tells for the 1.8 prereleases: the atomic read is tried the first
# time, and what it found is kept
const TIMERSET_ATOMIC = Threads.Atomic{Int8}(-1)
function timerfired(t::Timer)
    atomic = TIMERSET_ATOMIC[]
    if atomic < 0
        try
            set = getfield(t, :set, :acquire)
            TIMERSET_ATOMIC[] = 1
            return set
        catch ex
            ex isa InterruptException && rethrow()
            TIMERSET_ATOMIC[] = 0
            atomic = Int8(0)
        end
    end
    return atomic == 1 ? getfield(t, :set, :acquire) : getfield(t, :set)
end

# the finalizer. A stream that was aborted, or closed gracefully and handed to its
# socket's normal close, is left alone: that close may still be flushing, and needs
# nothing of the stream. One that was dropped without being closed is closed from a task: a
# finalizer may not wait, as a contended `ssl.lock` would make it, but the task may. No
# writer can be parked on it, the writer's task would keep it alive. The socket is as a
# rule collected along with the stream, and its own finalizer closes the handle before
# the task runs: then there is no close_notify to send and the stream is aborted, which
# frees the SSL object and nothing more. Only a socket that outlived the sweep gets the
# graceful close. A dropped stream is torn down, not shut down: close it to shut it
# down. (Collected as the process exits, the task never runs and the SSL object is not
# freed; the OS reclaims it with everything else.) A stream marked closed but neither
# aborted nor handed to the socket's normal close was closed gracefully and stopped on
# the way, a close under way keeping the stream alive: it is aborted, so that its socket
# does not stay open
function finalize!(ssl::SSLStream)
    if getfield(ssl, :closed)
        data = getfield(ssl, :data)
        data.aborted || data.handedoff || @async close(ssl, false)
        return
    end
    @async socketclosed(getfield(ssl, :io)) ? close(ssl, false) : close(ssl)
    return
end

# backwards compat
Base.getproperty(ssl::SSLStream, nm::Symbol) = nm === :bio_read_stream ? ssl : getfield(ssl, nm)

function drain!(ssl::SSLStream, pending)
    try
        drain!(getfield(ssl, :data), pending)
    catch
        # a failed socket write used to surface through the BIO callback as an SSL
        # error, which closed the stream; keep that so `isopen` does not report a
        # connection whose ciphertext never reached the peer as usable; the abort holds
        # interrupts back itself, so that a cancelled task still gets it done
        close(ssl, false)
        rethrow()
    end
end

Base.isreadable(ssl::SSLStream)::Bool = isopen(ssl) && isreadable(ssl.io)
Base.isopen(ssl::SSLStream)::Bool = Base.@lock(ssl.lock, !ssl.closed)
# not while a graceful close is under way, which refuses new writes; the stream is still
# open then, and readable
Base.iswritable(ssl::SSLStream)::Bool =
    Base.@lock(ssl.lock, !ssl.closed) && !closing(ssl) && isopen(ssl.io)
@noinline throwio(op) = throw(Base.IOError("$op requires ssl to be open", 0))

# the message of an SSL call that failed with `code`: its name, and what the thread's
# OpenSSL error queue holds of why, which reading takes off the queue, where a later
# call would otherwise take it for its own. The thread's queue alone: not `get_error`,
# which would also take an unrelated error another call left for its task
function sslcallerror(code)
    name = OpenSSLError(code).msg
    queue = rstrip(errorqueue())
    return isempty(queue) ? name : string(name, ": ", queue)
end

# this is a macro, but should be a function, but closures are stupid slow
# we use this to standardize the error handling for all of the SSL_*_ex functions:
# make the ccall under `ssl.lock`, check the error queue, and take the ciphertext the
# call produced while still holding the lock. Evaluates to `(ret, pending, err)`, for
# `finish_sslcall!` once every lock that must not be held across the socket write is
# released; `@geterror` is the two together.
macro sslcall(ssl, op, expr)
    # the temporaries are gensyms: the whole quote is escaped, and plain names would
    # clobber a caller's locals of the same name
    _err, _ret, _r, _e, _pending, _ended =
        gensym.(("err", "ret", "r", "e", "pending", "ended"))
    esc(quote
        local $_err = nothing
        local $_ret = SSL_ERROR_NONE
        # the call ends the stream (it failed, or the peer closed): set first in each such
        # branch, before anything that allocates, for the rest and the catch to go by
        local $_ended = false
        local $_pending = Base.@lock $ssl.lock begin
            # check that SSL is still open before ccall
            $ssl.closed && throwio($op)
            # clear the current error queue before openssl ccall
            clear_errors!()
            # do the ccall
            $_r = $expr
            # the rest in a `try`: cut short (an interrupt at an allocation) after the
            # call, what the call left in the buffer is not to go out with another call's,
            # nor the stream to stay open. The records of a call that did not fail are
            # lost, and the stream with them, as for a write cancelled under way (see
            # `drain!`): dropped, and the stream aborted under `ssl.lock` still, so that no
            # later call makes records after the gap; what a call that ended the stream
            # produced (a failed call's alert, or anything a call meeting the peer's
            # close_notify made) goes out with the abort, as it would have. A stream
            # aborted already takes nothing more
            try
                # we want to return one of our SSL return codes, regardless of error
                # SSL_peek_ex, SSL_write_ex, SSL_connect, SSL_accept and SSL_read_ex all
                # return 1 on success
                if $_r != 1
                    $_e = get_error($ssl.ssl, $_r)
                    if $_e == SSL_ERROR_ZERO_RETURN
                        # the peer sent a close_notify, so no more reading is possible
                        $_ended = true
                        $_err = Base.IOError("unexpected EOF", 0)
                    elseif $_e == SSL_ERROR_NONE || $_e == SSL_ERROR_WANT_READ || $_e == SSL_ERROR_WANT_WRITE
                        # WANT_READ: we need to read more data from the underlying socket
                        # WANT_WRITE: we need to write more data to the underlying socket;
                        # we don't expect to ever see this since we set up our SSL
                        # to do auto TLS (re)negotiation
                        $_ret = $_e
                    else
                        # this is usually some other kind of error, like a protocol error
                        # or OS-level IO error, just close the SSL connection and throw
                        # notably, the openssl docs say we should *not* call ssl_disconnect
                        # in this case, hence the `false` arg to close
                        $_ended = true
                        $_err = Base.IOError(sslcallerror($_e), 0)
                    end
                end
                if !$_ended
                    take!(getfield($ssl, :data))
                else
                    # closed and aborted under the lock we already hold, in one go; the
                    # abort sends the alert OpenSSL queued for the peer, from a task
                    abortlocked!($ssl)
                end
            catch
                # in a hold of its own from here, `abortlocked!`'s beginning only with its
                # call; the buffer never handed out, emptied in place, which cannot fail
                # (what the closure needs bound anew: captured as they are, assigned in
                # the section, they would be boxed on every call)
                let failed = $_ended
                    holdinterrupts() do
                        failed || empty!(getfield($ssl, :data).buf)
                        abortlocked!($ssl)
                    end
                end
                rethrow()
            end
        end
        ($_ret, $_pending, $_err)
    end)
end

# the second half of an SSL call: throw when it failed (the stream was closed and
# aborted in `@sslcall` already, the abort sending the alert), otherwise
# write what it produced to the socket and hand back its return code. The write BIO
# only buffers, so this is where the socket write happens, and the caller waits for the
# peer here rather than under `ssl.lock`.
# `detach` is for reads: what they produce is a reply to the peer that the reader has
# no reason to wait for, and waiting would put the reader behind a writer parked on a
# peer that is not reading; it is sent from a task, in its ticket's order like anything
# else.
function finish_sslcall!(ssl::SSLStream, ret::SSLErrorCode, pending, err; detach::Bool=false)
    # failed: the stream was closed and aborted in `@sslcall` already
    err === nothing || throw(err)
    if detach && pending !== nothing
        background() do
            try
                drain!(ssl, pending)
            catch ex
                # `drain!` closed the stream; the reader finds that out on its next call
                @guarded @debug "SSL reply to the peer not sent" ex
            end
        end
    else
        drain!(ssl, pending)
    end
    return ret
end

macro geterror(ssl, op, expr, detach=false)
    esc(:(finish_sslcall!($ssl, (@sslcall $ssl $op $expr)...; detach=$detach)))
end

# waits for bytes on the socket for an SSL call that asked for more, and says whether
# the socket is at its EOF instead. EOF does not close the stream, no more than `eof` on
# a socket does: the peer may have shut down its side only, and a reply may still be
# due; the handshakes, which have nothing usable then, close it themselves. An error on
# the socket, a reset say, is the end of the transport and the stream with it: closed
# here, and rethrown, so that the next call does not run into the same error again.
function socketeof(ssl::SSLStream)
    try
        return eof(ssl.io)
    catch ex
        ex isa Base.IOError || rethrow()
        close(ssl, false)
        rethrow()
    end
end

# the write BIO buffers the whole output of one `SSL_write_ex` before `drain!` moves it
# to the socket, so cap how much plaintext goes into a single call to bound that buffer.
# One TLS record's worth: the chunk is then one record, which fits the spare buffer (see
# `keepspare!`), so a long write reuses one buffer instead of growing a new one to the
# size of the call
const SSL_WRITE_CHUNK = UInt(16 * 1024)
# the largest chunk kept as the spare: a whole `SSL_WRITE_CHUNK` record, with room for
# its header, padding and tag, and for a KeyUpdate or an alert riding along
const SPARE_MAX = Int(SSL_WRITE_CHUNK) + 1024

function Base.unsafe_write(ssl::SSLStream, in_buffer::Ptr{UInt8}, in_length::UInt)
    # nothing to write: nothing to refuse either, whatever state the stream is in
    in_length == 0 && return 0
    counted = Ref(false)
    try
        # counted in, for a graceful close to wait for, or refused, should one have
        # begun; either way before waiting for the writer lock behind a writer that may
        # be parked. With an interrupt held back until the flag says which, so that
        # the count goes down again whatever ends the write. (With `disable_sigint`, the
        # hold has to begin and end with no `try` in between: leaving a `try` puts it
        # back as it was on entry)
        holdinterrupts(() -> countin!(ssl, counted))
        # refused: without taking `ssl.lock`, which a writer retrying in a loop would
        # otherwise keep from the close; `closed` read as is only picks the message, the
        # stream reporting open until the close is through
        if !counted[]
            ssl.closed && throwio(:unsafe_write)
            throw(Base.IOError("unsafe_write: the stream is being closed", 0))
        end
        # counted: a stream closed by an abort refuses it too
        Base.@lock(ssl.lock, ssl.closed) && throwio(:unsafe_write)
        # one writer at a time, from the first chunk to the last, so that a write arrives
        # in one piece however many chunks it takes, as it did with one `SSL_write_ex`
        # for the whole of it. Readers do not take this lock
        Base.@lock ssl.wlock begin
            nwritten = 0
            # per call, as `unsafe_read`'s: under `ssl.wlock` a shared one would be safe
            # too, but a field would be one more thing kept in step with the lock
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
                    nwritten += Base.bitcast(Int, writebytes[])
                elseif ret == SSL_ERROR_WANT_WRITE
                    flush(ssl.io)
                elseif ret == SSL_ERROR_WANT_READ
                    # this means write is waiting for more data from the underlying socket
                    # so call eof on the socket to wait for more bytes to come in
                    socketeof(ssl) && throw(EOFError())
                end
            end
        end
    finally
        counted[] && endwrite!(ssl)
    end
    return Base.bitcast(Int, in_length)
end

# the sign bit, whatever the width of `Int`; the count takes the bits below it
const CLOSING = typemin(Int)
const INFLIGHT = typemax(Int)

closing(ssl::SSLStream) = ssl.wstate[] & CLOSING != 0
writesinflight(ssl::SSLStream) = ssl.wstate[] & INFLIGHT

# counts a write in, unless a graceful close has begun; says which in `counted`
function countin!(ssl::SSLStream, counted)
    while true
        v = ssl.wstate[]
        v & CLOSING == 0 || return
        if Threads.atomic_cas!(ssl.wstate, v, v + 1) == v
            counted[] = true
            return
        end
    end
end

# counts a write out, then tells the close, under the lock the condition needs. With an
# interrupt held back, so that neither is cut short once begun; and never below zero:
# from there it would borrow through the `CLOSING` bit, clear it and leave a count no
# close could wait out. Not an error to throw, being called from a `finally` where it
# would replace the write's own error: it is logged. An interrupt that lands before
# this leaves the close to find out when its watch gives up
function endwrite!(ssl::SSLStream)
    # all of it: the lock and the log are cancellation points where there are such
    holdinterrupts() do
        countout!(ssl) ||
            @guarded @error "OpenSSL: a write counted out that was never counted in"
        surely(() -> notify(ssl.closecond), ssl.lock)
    end
    return
end

function countout!(ssl::SSLStream)
    while true
        v = ssl.wstate[]
        v & INFLIGHT == 0 && return false
        Threads.atomic_cas!(ssl.wstate, v, v - 1) == v && return true
    end
end

"""
    Sockets.connect(ssl::SSLStream; require_ssl_verification=true, timeout=Inf)

Runs the client side of the TLS handshake on `ssl` and returns once it is complete, the
peer's certificate verified unless `require_ssl_verification` is false. Throws
`EOFError` when the peer goes away first, `IOError` when the handshake fails, `IOError`
once `timeout` seconds have passed since the call began, however far the handshake got,
and `OpenSSLError` when the peer's certificate does not verify (in a context that
verifies during the handshake itself, that is a failed handshake, an `IOError`); the
stream is closed in each of those cases. `timeout` is a positive number of seconds, or
`Inf` for none.
"""
function Sockets.connect(ssl::SSLStream; require_ssl_verification::Bool=true, timeout::Real=Inf)
    # the peer's certificate checked as the handshake's last step, within its guard: a
    # stream whose peer was not checked, whatever ended the check early, an interrupt
    # included, is not to be used, and is closed with the rest of a half-done handshake
    verify = require_ssl_verification ? (() -> verifypeer!(ssl)) : nothing
    handshake!(ssl, :connect, timeout; finish=verify) do
        @geterror ssl :connect ssl_connect(ssl.ssl)
    end
    return
end

function verifypeer!(ssl::SSLStream)
    failure = Base.@lock ssl.lock begin
        ssl.closed && throwio(:verify_result)
        ret = ccall(
            (:SSL_get_verify_result, libssl),
            Cint,
            (SSL,),
            ssl.ssl)
        ret == 0 ? nothing : unsafe_string(ccall(
            (:X509_verify_cert_error_string, libcrypto),
            Ptr{UInt8},
            (Cint,),
            ret))
    end
    # get peer certificate
    if failure === nothing && get_peer_certificate(ssl) === nothing
        failure = "No peer certificate"
    end
    failure === nothing || throw(OpenSSLError(failure))
    return
end

# runs a handshake to completion: `step` does one round of it (the ccall under
# `@geterror`) and returns the code; more bytes are waited for on the socket, whose EOF
# ends the stream. Then read ahead is set: a recommended optimization when an SSL
# connection is only ever read from sequentially, which it is, there being no internal
# buffering of decrypted bytes. `finish`, if given, is the last step: inside the guard
# that closes a half-done stream, and under the deadline, the handshake being done only
# once it is. It runs on a stream that the deadline or another task may close at any
# point, so it must take `ssl.lock` and check `ssl.closed` before it touches the SSL
# object, as `verifypeer!` does; its own error names its own op.
#
# `timeout` is one deadline for the whole handshake. When it passes, the timer aborts
# the stream, which wakes a round waiting on the socket and fails one stuck writing to
# a peer that does not read, and notes that it did so the error says so. Whether the
# handshake completed first is decided under `ssl.lock`, in the same section that marks
# the stream closed, since a timer that went off as the handshake completed still runs
# its callback after `close(timer)`. `Timer` counts on the monotonic clock.
function handshake!(step, ssl::SSLStream, op::Symbol, timeout::Real; finish=nothing)
    # positive seconds, or none. Zero is refused rather than read as either "none" or
    # "passed already", both of which some callers would mean; and `Timer` cannot count
    # past about 1e16 seconds, so from 1e9 on (over thirty years) it is none as well
    timeout > 0 ||
        throw(ArgumentError("$op: timeout must be a positive number of seconds or Inf, got $timeout"))
    timeout >= 1e9 && (timeout = Inf)
    # :running, then :done or :timedout, whichever comes first under `ssl.lock`
    state = Ref(:running)
    timer = timeout == Inf ? nothing : ticker(timeout) do _
        cause = nothing
        try
            Base.@lock ssl.lock begin
                if state[] === :running && !ssl.closed
                    state[] = :timedout
                    abortlocked!(ssl)
                end
            end
        catch ex
            ex isa InterruptException || (cause = ex)
            rethrow()
        finally
            # timed out, by this run or by one that did not get to the end, whose end is
            # still to do (done, or closed because the handshake failed or someone closed
            # it, is not the deadline's to act on). Read outside the lock: only these
            # runs, one after another in the ticker's task, ever set :timedout. Nothing a
            # failed handshake produced is worth waiting for: the socket goes at once,
            # which also fails a round parked writing to a peer that does not read;
            # whatever the abort did, which the ticker then hears of, and which the cut
            # names should it fail too
            state[] === :timedout && cut!(getfield(ssl, :data), nothing, cause)
        end
    end
    try
        while true
            ret = step()
            if ret == SSL_ERROR_NONE
                break
            elseif ret == SSL_ERROR_WANT_READ
                # more bytes from the peer are needed, wait for them; the catch below
                # closes the stream should the peer be gone
                socketeof(ssl) && throw(EOFError())
            else
                # WANT_WRITE cannot happen, the write BIO takes everything
                throw(Base.IOError("$op: unexpected $ret from the handshake", 0))
            end
        end
        # the last step still under the deadline, which it counts toward (checking for a
        # closed stream itself, see above)
        finish === nothing || finish()
        Base.@lock ssl.lock begin
            state[] === :running && (state[] = :done)
            # closed meanwhile: by the deadline, which the catch reports as such, or by
            # another task. Or the deadline passed with the stream somehow still open (its
            # abort having failed): the deadline decides, not what the abort left
            (ssl.closed || state[] === :timedout) && throwio(op)
            ccall(
                (:SSL_set_read_ahead, libssl),
                Cvoid,
                (SSL, Cint),
                ssl.ssl,
                Cint(1))
        end
    catch ex
        # whatever ended the handshake, an interrupt included, a half-done stream is of
        # no use: it is closed. Then, the abort makes the round under way fail with
        # whatever it fails with, and the deadline is the cause; anything else is not
        # ours to replace. Nor is it replaced by the abort failing, which is logged. An
        # interrupt held off the abort is thrown once it is done; an exception thrown into
        # the task while the abort waits for the lock goes on at once, the abort left to a
        # task of the library's (see `abortsurely!`)
        close(ssl, false)
        if ex isa Union{Base.IOError, EOFError} && Base.@lock(ssl.lock, state[] === :timedout)
            throw(Base.IOError("$op: the handshake timed out", 0))
        end
        rethrow()
    finally
        timer === nothing || close(timer)
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

"""
    Sockets.accept(ssl::SSLStream; timeout=Inf)

Runs the server side of the TLS handshake on `ssl` and returns once it is complete.
Throws `EOFError` when the peer goes away first, `IOError` when the handshake fails,
and `IOError` once `timeout` seconds have passed since the call began, however far the
handshake got; the stream is closed in each of those cases. `timeout` is a positive
number of seconds, or `Inf` for none.

Before 1.6.2 the call did one round of the handshake and threw `OpenSSLError` whenever
it needed more bytes from the peer, and the caller retried. Those loops still work, they
get the completed handshake on the first call, but they no longer see `OpenSSLError`:
the errors are `EOFError` and `IOError` now. A deadline such a loop enforced between
attempts is what `timeout` is for.
"""
function Sockets.accept(ssl::SSLStream; timeout::Real=Inf)
    handshake!(ssl, :accept, timeout) do
        @geterror ssl :accept ccall(
            (:SSL_accept, libssl),
            Cint,
            (SSL,),
            ssl.ssl)
    end
    return
end

"""
    Read from the SSL stream.
"""
function Base.unsafe_read(ssl::SSLStream, buf::Ptr{UInt8}, nbytes::UInt)
    nread = 0
    # per call, not per stream: readers take no lock across their rounds, and a count
    # shared by the stream, overwritten by another reader's call before this one read it
    # back, would lose or duplicate bytes, or count bytes never read (and return more
    # than `nbytes`)
    readbytes = Ref{Csize_t}(0)
    while nread < nbytes
        # `true`: what the read produces goes out from a task, see `finish_sslcall!`
        ret = @geterror ssl :unsafe_read ccall(
            (:SSL_read_ex, libssl),
            Cint,
            (SSL, Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
            ssl.ssl,
            buf + nread,
            nbytes - nread,
            readbytes
        ) true
        if ret == SSL_ERROR_NONE
            nread += Base.bitcast(Int, readbytes[])
        elseif ret == SSL_ERROR_WANT_READ
            # this means read is waiting for more data from the underlying socket
            # so call eof on the socket to wait for more bytes to come in
            socketeof(ssl) && throw(EOFError())
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
        # the peek runs under `eoflock`; what it produced is sent after the lock is
        # released (see the end of the loop), so the result has to come out of the block
        ret, pending, err = Base.@lock ssl.eoflock begin
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
            # check condition now that we have eoflock since another task may have
            # succeeded in getting bytes processed
            isopen(ssl) || return true
            bytesavailable(ssl) > 0 && return false
            # no processed bytes available, check if there are unprocessed bytes
            if !haspending(ssl)
                # no unprocessed bytes, call eof to get more unprocessed
                if socketeof(ssl) && !haspending(ssl)
                    # if eof and there are no pending, then we are eof. Not closed: as
                    # with `eof` on a socket, the peer may have shut down its side only
                    return true
                end
            end
            # at this point, we know there are at least unprocessed bytes
            # buffered, so we call SSL_peek to get the next record processed,
            # which still might not result in bytesavailable > 0
            ret, pending, err = @sslcall ssl :peek ccall(
                (:SSL_peek_ex, libssl),
                Cint,
                (SSL, Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
                ssl.ssl,
                ssl.peekbuf,
                1,
                ssl.peekbytes
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
                    # so this is the end of the stream. Looping instead would spin:
                    # `haspending` stays true for the partial record and `eof(ssl.io)`
                    # returns at once, without ever yielding.
                    socketeof(ssl) && return true
                end
                continue
            end
            (ret, pending, err)
        end
        # processing the record produced something for the peer (a KeyUpdate reply; the
        # alert of a record that failed goes with the abort): send it, or fail, without
        # holding `eoflock`. A writer parked on a peer that is not reading would otherwise
        # hold every other reader up through this lock. Then go round again: whether the
        # peek made bytes available is re-checked at the top.
        finish_sslcall!(ssl, ret, pending, err; detach=true)
    end
    bytesavailable(ssl) > 0 && return false
    return !isopen(ssl)
end

"""
    close(ssl::SSLStream, shutdown::Bool=true)

Closes the stream and its socket; returns `nothing`, possibly before all of it is done:
an abort sends what was produced before it (bar anything after a record already lost,
the records of a call cut short before it took them, and a close_notify a graceful close
cut short produced but never took), and the socket is closed, in the background; a
second close of the same kind returns while the first is under way, while an abort
during a graceful close takes over from it (see below). With `shutdown`, gracefully:
writes issued on other tasks before the close finish first, the stream staying readable
while they do, and one issued after it fails, as `iswritable` tells from the start of
the close; then the peer is sent the close_notify, and the socket is closed with what is
queued on it flushed. That can wait behind a writer parked on a peer that is not
reading, for as long as the peer keeps taking bytes; once nothing has moved for
`CLOSE_GRACE` seconds the parked write is failed and the close finishes as an abort. A
stream that has lost a record, one that failed to reach the peer, likewise ends aborted,
with no close_notify: none can follow the gap. A second graceful close, while the first
is under way or after it, returns at once.

`close(ssl, false)` aborts. The stream is marked closed at once, and nothing produced
from then on is sent: a write under way fails at its next chunk, a new one at once.
What was produced before still goes out, in order (up to a record lost already, which
refuses all after it), and then the socket is closed. A
writer parked on a peer that is not reading holds that up until `ABORT_GRACE` seconds
pass with nothing moving; then the socket is closed outright and the parked write
fails. A graceful close still waiting for writes issued before it stops waiting at
once and returns; one whose close_notify was already taken sends it first, being ahead
of the abort.
"""
function Base.close(ssl::SSLStream, shutdown::Bool=true)
    if shutdown
        closegracefully!(ssl)
    else
        # abort: tear the transport down whether or not the stream was closed before,
        # a graceful close waiting behind a parked writer included. The wait for the lock
        # held against interrupts too: this is how a cancelled task cleans up
        abortsurely!(ssl)
    end
    return
end

# aborts the stream, as `close(ssl, false)` does; every cleanup that aborts a stream goes
# through this. With an interrupt held back, and `ssl.lock` taken surely: should an
# exception be thrown into the task while it waits for it, the abort and what follows it
# are left to a task of the library's, and the exception goes on (see `surely`). The
# abort failing is logged, not thrown, a cleanup's own error being the one to report
function abortsurely!(ssl::SSLStream)
    holdinterrupts() do
        surely(ssl.lock; then=r -> r === nothing || abortfailed!(ssl, r...)) do
            try
                abortlocked!(ssl)
                nothing
            catch ex
                # whether the stream got marked closed read here, under the lock, rather
                # than in a wait for it after
                (ex, catch_backtrace(), ssl.closed)
            end
        end
    end
    return nothing
end

# after an abort that failed, outside `ssl.lock`: if it got as far as marking the stream
# closed, the socket goes all the same, as a watch's does: a stream that reads as closed
# does not keep its socket open. If not (only a failure setting up its hold, the stream
# being marked closed first), the stream reads as open, and the socket is left to it.
# Said first, the cut saying itself should it fail
function abortfailed!(ssl::SSLStream, failure, bt, closed::Bool)
    what = closed ? "cutting its socket" : "the stream is left open"
    @guarded @error "OpenSSL: aborting a stream failed; $what" exception=(failure, bt)
    closed && cut!(getfield(ssl, :data), nothing, failure)
    return nothing
end

# marks the stream closed and aborts it, in one go: under `ssl.lock`, which the caller
# holds, and with an interrupt held back, so that nothing stops in between. Nothing in
# here waits but, on a failure, the giving up of a ticket and the cut (see `surely`),
# where a task injected with an exception could still land. Whatever fails on the way,
# the stream ends up marked closed (first, before anything that allocates) and claimed
# (in a `finally`), and either its abort's task set going or, should that task not have
# been made, its socket cut outright here, a parked write with it: every caller gets the
# same, and a stream is only ever marked closed without an abort by a graceful close.
# Failures are logged, last and one by one, so that a logger that throws stops none of
# this; nor is what it throws taken for the abort's. A second abort has nothing to add
function abortlocked!(ssl::SSLStream)
    holdinterrupts() do
        data = getfield(ssl, :data)
        data.aborted && return
        wasopen = !ssl.closed
        ssl.closed = true
        closefailure = nothing
        taskfailure = nothing
        taken = nothing
        task = nothing
        try
            try
                # the rest of the close (see `closelocked!`), first, so that nothing after
                # can keep it from being done: the SSL object freed, and the alert, if
                # there is one, taken with the stream marked closed, so no ticket can
                # follow it
                ticket = data.nextticket
                try
                    # on a stream closed already, by a graceful close cut short on its
                    # way perhaps, the rest of the close done all the same (a second
                    # free does nothing)
                    # whatever a close cut short left in the buffer is not sent: with
                    # it emptied, the close hands out nothing
                    wasopen || empty!(data.buf)
                    taken = closerest!(ssl, false)
                catch ex
                    # the alert given up, its ticket too should it have been handed out
                    # (`closerest!` frees the SSL object whatever it does)
                    empty!(data.buf)
                    data.nextticket == ticket || abandon!(data, ticket)
                    closefailure = (ex, catch_backtrace())
                end
                try
                    task = abortertask(ssl, taken)
                catch ex
                    taskfailure = (ex, catch_backtrace())
                end
            finally
                # claimed, whatever went wrong above: the task set going, or else the
                # alert's ticket given up and the socket cut, the cut whatever the giving
                # up does
                data.aborted = true
                if task === nothing
                    try
                        taken === nothing || abandon!(data, taken.ticket)
                    finally
                        cause = taskfailure === nothing ? nothing : taskfailure[1]
                        cut!(data, nothing, cause)
                    end
                else
                    schedule(task)
                end
            end
        finally
            # whatever the above threw
            logabort("the rest of its close failed; its alert is given up", closefailure)
            logabort("making its task failed; its socket is cut", taskfailure)
        end
    end
    return nothing
end

# logs what went wrong in an abort, if anything did (see `@guarded`)
function logabort(what, failure)
    failure === nothing && return
    @guarded @error "OpenSSL: aborting a stream: $what" exception=failure
    return
end


# the graceful close's: marks the stream closed, produces the close_notify and frees the
# SSL object; must run under `ssl.lock`, which the caller keeps holding. Returns the
# close_notify for `closegracefully!` to send (nothing should a record have been lost
# already, see `closerest!`). On a stream closed already, nothing: no ticket is handed
# out once the stream is marked closed, which is what lets the abort send everything
# ticketed before it and refuse nothing
function closelocked!(ssl::SSLStream)
    ssl.closed && return nothing
    ssl.closed = true
    return closerest!(ssl, true)
end

# the rest of a close, once the stream is marked closed: the graceful close's through
# `closelocked!`, the abort's (with no close_notify) through `abortlocked!`. Returns
# what OpenSSL left in the write BIO, the close_notify or the alert of the call that
# failed. Freeing the SSL object twice would do nothing the second time (`free` clears
# the pointer)
function closerest!(ssl::SSLStream, shutdown::Bool)
    # the SSL object freed whatever the steps before it did: a graceful close waiting
    # for writes stops waiting for them, then the close_notify is produced. Not when
    # that step did not go through, nor when a record was lost already, on another task
    # whose abort has yet to begin (a read's reply sent from a task of its own, a
    # handshake round, a write whose abort was left to a task of the library's): the
    # close_notify would be refused, the peer getting none, and `SSL_shutdown` would
    # still mark the session as shut down cleanly, which keeps it resumable
    notified = false
    try
        notify(ssl.closecond)
        notified = true
    finally
        try
            if shutdown && notified
                # the check and `SSL_shutdown` in one section, so that no loss recorded
                # before the close_notify exists goes unseen (`SSL_shutdown` only buffers
                # what it produces, the write BIO callback taking no lock); one recorded
                # after still refuses it, a close_notify then produced in good faith. A
                # plain wait for `data.cond`, not `surely`: an exception landing in it
                # costs the close_notify, and the close aborts
                data = getfield(ssl, :data)
                Base.@lock data.cond begin
                    data.lostfrom == typemax(Int) && ssl_disconnect(ssl.ssl)
                end
            end
        finally
            free(ssl.ssl)
        end
    end
    return take!(getfield(ssl, :data))
end

# how long, without any progress, an abort lets the records still to go out, its alert
# included, and the normal close of the socket take before the socket handle is closed
# under them. Progress resets it: a peer that reads, however slowly, is not cut off, so
# this bounds a stall, not the whole close. The same for a graceful close, which should
# ride out a peer that merely pauses: a stalled peer costs the close_notify, and the
# peer a truncation error. Both settable, for tests that would rather not wait
const ABORT_GRACE = Ref(1.0)
const CLOSE_GRACE = Ref(10.0)

# arms an `AbortWatch` over the socket, ticking every `grace` seconds
armwatch(ssl::SSLStream, grace::Real) =
    (watch = AbortWatch(ssl); ticker(t -> watch(t), grace; interval=grace))

# the graceful close. Writes issued before it finish first, as they did when one
# `SSL_write_ex` under the lock wrote the whole of each: the close waits until none is
# in flight before it marks the stream closed. Then the close_notify takes its turn
# behind the records before it, and the socket is closed the normal way, which flushes
# what is queued on it and sends a FIN. A writer parked on a peer that is not reading
# would hold either wait for good, so a watch bounds the stall: once nothing has moved
# for `CLOSE_GRACE` it fails the parked write; the close_notify is then refused for the
# gap, or never produced, and the close turns into an abort. An abort meanwhile ends the
# wait. A second graceful close finds the first under way or done and does nothing more.
# Must be called without `ssl.lock` held.
function closegracefully!(ssl::SSLStream)
    io = ssl.io
    began = false
    timer = nothing
    sent = false
    try
        # inside the `try`: once the close has begun, the stream must end up closed
        Base.@lock ssl.lock begin
            # the bit set atomically: a write counting in at the same moment either
            # gets in first and is waited for, or sees the bit and is refused
            began = !ssl.closed && Threads.atomic_or!(ssl.wstate, CLOSING) & CLOSING == 0
        end
        began || return
        # the watch, should it give up, marks the stream closed, which ends the wait
        timer = armwatch(ssl, CLOSE_GRACE[])
        pending = Base.@lock ssl.lock begin
            # until no write issued before the close is in flight, or the stream is
            # closed: by an abort, or by the watch giving up
            while writesinflight(ssl) > 0 && !ssl.closed
                wait(ssl.closecond)
            end
            # aborted meanwhile: then nothing comes back
            closelocked!(ssl)
        end
        if pending !== nothing
            # on failure this aborts the stream itself
            drain!(ssl, pending)
            sent = true
        end
    catch err
        # the peer being gone is expected here; an interrupt or a cancellation of the
        # task is not ours to swallow
        err isa Union{Base.IOError, EOFError} || rethrow()
        @guarded @debug "SSL close_notify not sent" err
    finally
        # with an interrupt held back: a close interrupted while it waited still has to
        # end the stream, and the abort takes locks, cancellation points where there are
        # such
        began && holdinterrupts() do
            # no close_notify, from a shutdown that produced none, one that did not go
            # out, or an abort meanwhile: the abort is the close that copes with a parked
            # writer
            finish = function ()
                timer === nothing || close(timer)
                if sent
                    background(() -> through(() -> closequietly(io)))
                else
                    close(ssl, false)
                end
            end
            # handed off first, under `ssl.lock`: the watch's giving up checks it there,
            # and a tick that raced the timer's close stands down. The lock taken surely,
            # the hand-off and the rest of the close left to a task of the library's
            # should an exception be thrown into this one meanwhile (see `surely`)
            if sent
                data = getfield(ssl, :data)
                surely(() -> (data.handedoff = true), ssl.lock; then=_ -> finish())
            else
                finish()
            end
        end
    end
    return
end

# the abort's task, for `abortlocked!` to set going once it has marked the stream
# closed, `alert` being the alert of the call that failed, or nothing. Nothing
# produced after that point is sent any more (no call makes records nor takes a ticket
# once the stream is marked closed). What was produced before it is protocol-wise fine
# to send, so it goes out in order, the alert last, and once every ticket is through the
# socket is closed the normal way. A writer parked on a peer that is not reading would
# hold that up for good, so an `AbortWatch` closes the socket handle outright once
# `ABORT_GRACE` passes without progress. With nothing to send and nothing in flight, the
# socket is simply closed.
function abortertask(ssl::SSLStream, alert::Union{Nothing, PendingWrite})
    data = getfield(ssl, :data)
    io = ssl.io
    # every wait through a Ctrl-C landing on this task (see `runwhole`, `through`); the
    # alert's socket write is no wait to hold one off across, having no bound: one landing
    # there gives the alert up, cutting the socket, as for any write cut short
    return unscheduled() do
        timer = nothing
        try
            # nothing to send and nothing in flight: the socket is simply closed
            idle = alert === nothing &&
                through(() -> Base.@lock(data.cond, drained(data)))
            if !idle
                timer = runwhole(() -> armwatch(ssl, ABORT_GRACE[]))
                try
                    drain!(data, alert)
                catch ex
                    # the drain has passed its ticket on whatever ended it
                    if ex isa InterruptException
                        lostinterrupt()
                    else
                        @guarded @debug "SSL alert not sent" ex
                    end
                end
                # the records ticketed before the abort are still going out; closing the
                # socket now would take its write side from under them. The watch bounds
                # this wait: once it has cut the socket, a ticket that never comes
                # through (its task stopped before draining it) holds it no more
                through() do
                    Base.@lock data.cond begin
                        while !drained(data) && !data.cut
                            wait(data.cond)
                        end
                    end
                end
            end
            through(() -> closequietly(io))
        catch ex
            # the watch not armed, or anything else gone wrong: the socket goes all the
            # same, outright, a parked write with it; said after
            try
                cut!(data, nothing, ex)
            finally
                @guarded @error "OpenSSL: the abort of a stream failed; its socket is cut" exception=caught(ex)
            end
        finally
            # `close` waits for the handle to be closed on every supported Julia, so the
            # watch has nothing left to do; keeping it for another period would make a
            # process that is exiting wait for it. Unless the close threw: then the
            # watch stays on
            timer === nothing || !socketclosed(io) || close(timer)
        end
    end
end

# closes the socket, quietly about the peer being gone; and not at all once the handle
# is gone, which `close` would refuse with an error: the socket's finalizer may have run
# before the stream's
function closequietly(io::TCPSocket)
    socketclosed(io) && return nothing
    try
        Base.close(io)
    catch e
        e isa Base.IOError || rethrow()
    end
    return nothing
end

# the handle and status of a socket are the event loop's, to be read under its lock
function withiolock(f)
    Base.iolock_begin()
    try
        return f()
    finally
        Base.iolock_end()
    end
end

socketclosed(io::TCPSocket) = withiolock(() -> handlegone(io))

# under `iolock`. A closed socket's handle is freed but, from Julia 1.9 on, not nulled:
# the status is what says whether the handle may still be touched
handlegone(io::TCPSocket) = io.handle == C_NULL || io.status == Base.StatusClosed

# the watchdog of an abort or a close: called every grace period, it closes the socket
# handle outright when nothing has moved since the last time. A record going out moves the
# turn; bytes of a record under way leaving for the kernel shrink libuv's write queue,
# so a peer that reads slowly is not cut off. On Windows libuv only takes a write off
# the queue once it is complete, so there a slowly read record is cut off after one
# period with no turn passed. Stops itself once the socket is closed.
mutable struct AbortWatch
    # the stream: when the watch gives up it marks it closed as well, which ends a
    # graceful close's wait for the writes in flight; for an abort's watch it is closed
    # already, and that does nothing
    stream::SSLStream
    turn::Int
    queued::Csize_t
end
AbortWatch(ssl::SSLStream) = AbortWatch(ssl, watchstate(ssl)...)

# the turn and libuv's write queue: what moves when bytes go out
function watchstate(ssl::SSLStream)
    data = getfield(ssl, :data)
    return Base.@lock(data.cond, data.turn), writequeuesize(getfield(ssl, :io))
end

function (watch::AbortWatch)(timer::Timer)
    stream = watch.stream
    data = getfield(stream, :data)
    # the whole decision under `ssl.lock`, where a graceful close hands off: a close that
    # got its close_notify out and handed the socket to its normal close is done with its
    # watch, and one whose close_notify went out after this last sampled has moved. Else
    # the socket closed already, by someone else, or nothing moved: either way no write
    # in flight can finish now, and the watch gives up
    verdict = :moved
    cause = nothing
    try
        Base.@lock stream.lock begin
            if data.handedoff
                verdict = :stand
            else
                moved = false
                if !socketclosed(getfield(stream, :io))
                    turn, queued = watchstate(stream)
                    moved = (turn, queued) != (watch.turn, watch.queued)
                    watch.turn, watch.queued = turn, queued
                end
                if !moved
                    # the verdict stands whatever the abort does
                    verdict = :gaveup
                    abortlocked!(stream)
                end
            end
        end
    catch ex
        # failed before a verdict: a watch that cannot judge progress gives up, rather
        # than leave the stall it bounds unbounded. Not for an interrupt, which is not
        # the watch's to judge by: that tick is lost, as in any timer, and the next one
        # judges
        if !(ex isa InterruptException)
            verdict === :moved && (verdict = :gaveup)
            cause = ex
        end
        rethrow()
    finally
        if verdict === :gaveup
            # the socket goes, which fails a parked write, and the watch stops; whatever
            # went wrong above, which the ticker then hears of, and which the cut names
            # should it fail too
            try cut!(data, nothing, cause) finally close(timer) end
        elseif verdict === :stand
            close(timer)
        end
    end
    return
end

# bytes handed to libuv for the socket that it has not passed to the kernel yet. Zero
# when the socket is gone, or should libuv not answer (it has since 1.19; Julia 1.6
# ships 1.42): the watch then goes by the turn alone.
function writequeuesize(io::TCPSocket)
    withiolock() do
        handlegone(io) && return Csize_t(0)
        try
            return ccall(:uv_stream_get_write_queue_size, Csize_t, (Ptr{Cvoid},), io.handle)
        catch
            return Csize_t(0)
        end
    end
end

# set only by tests, to take the fallback below as if the internals were gone
const FORCECLOSE_FALLBACK = Ref(false)

# chunks kept alive for writes libuv may still hold, see `forceclose!`
const KEPT = Base.IdSet{Any}()
const KEPT_LOCK = ReentrantLock()

# set only by tests: called with the socket and the chunk whenever a chunk is kept
const ONKEEP = Ref{Any}(nothing)

# closes the socket handle outright: the writes queued on it fail with `ECANCELED`
# instead of being flushed first, as `close(::TCPSocket)` would do. What the kernel
# already holds it goes on delivering, unless it also holds inbound bytes never read,
# in which case (on Linux at least) it resets the connection and drops it all: the
# peer then sees a reset where records were counted as sent. A handle `uv_close` was
# already called on must not get a second call, a pending shutdown from `close` is no
# obstacle. This is what `close` itself does with a socket that never connected, and it
# is built on the same internals (checked on Julia 1.10, 1.12 and the 1.14 nightly);
# should they be gone, fall back to the normal close, which then may wait behind a
# parked write. Should they change in meaning instead, `CancelledCloser` and
# `AbortDuringGracefulClose` fail: a parked write is not failed any more.
#
# `keep` is the chunk of a write cancelled while under way, which libuv still holds a
# pointer into and nothing else keeps alive any more. Closing the handle outright
# cancels that write, but not necessarily at once (on Windows an overlapped send is
# cancelled when its completion comes in); the normal close of the fallback does not
# cancel it at all. Either way the chunk is kept referenced until the socket is closed
function forceclose!(io::TCPSocket, keep=nothing)
    outright = false
    try
        FORCECLOSE_FALLBACK[] && error("the fallback, taken on purpose")
        withiolock() do
            if !handlegone(io) && ccall(:uv_is_closing, Cint, (Ptr{Cvoid},), io.handle) == 0
                ccall(:jl_forceclose_uv, Cvoid, (Ptr{Cvoid},), io.handle)
                io.status = Base.StatusClosing
            end
        end
        outright = true
    catch err
        @guarded @debug "could not close the socket handle outright" err
    end
    (outright && keep === nothing) && return
    background() do
        if keep !== nothing
            # the chunk kept, by the task that holds it till then, one of the library's
            # that nothing can throw into but a Ctrl-C, whole (see `runwhole`)
            runwhole(() -> Base.@lock(KEPT_LOCK, push!(KEPT, keep)))
            # not in a hold: the hook is the tests' code, and catches its own
            onkeep(io, keep)
        end
        # the normal close: after the outright one it waits for the handle to be
        # released, otherwise it is the close; through interrupts (see `through`). The
        # chunk is let go only once the socket is closed, whole, and else stays held: a
        # leak, not a pointer into freed memory
        through(() -> closequietly(io))
        keep === nothing ||
            runwhole(() -> socketclosed(io) && Base.@lock(KEPT_LOCK, delete!(KEPT, keep)))
    end
    return
end

# the tests' hook, told once a chunk is kept, on the task that keeps it; nothing it
# throws gets in the way. Set after that task began, as a rule, so newer than its world
function onkeep(io, keep)
    hook = ONKEEP[]
    hook === nothing && return
    try
        Base.invokelatest(hook, io, keep)
    catch ex
        if ex isa InterruptException
            lostinterrupt()
        else
            @guarded @error "OpenSSL: the ONKEEP hook failed" exception=caught(ex)
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
