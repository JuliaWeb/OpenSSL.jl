module OpenSSL

using BitFlags
using Dates
using OpenSSL_jll
using Sockets

"""
    [x] Free BIO
    [ ] Free BIOMethod
    [x] Free on BIOStream
    [x] Close SSLContext
    [x] BIOStream method (callbacks)
    [x] Store the SSLContext (part of SSLStream)
"""

export TLSv12ClientMethod, SSLStream, BigNum, EvpPKey, RSA, Asn1Time, X509Name, X509Certificate, EVPCipherContext, EVPBlowFishCBC, EVPBlowFishECB,
       EVPBlowFishCFB, EVPBlowFishOFB, EVPAES128CBC, EVPAES128ECB, EVPAES128CFB, EVPAES128OFB, EVPDigestContext, digest_init, digest_update, digest_final,
       digest, EVPMDNull, EVPMD2, EVPMD5, EVPSHA1, rsa_generate_key, add_entry, sign_certificate, adjust, eof, bytesavailable, read, unsafe_write, connect,
       get_peer_certificate, HTTP2_ALPN, UPDATE_HTTP2_ALPN

const Option{T} = Union{Nothing,T} where {T}

const HTTP2_ALPN = "\x02h2"
const UPDATE_HTTP2_ALPN = "\x02h2\x08http/1.1"

"""
    These are used in the following macros and are passed to BIO_ctrl().
"""
@enum(BIOCtrl::Cint,
      # opt - rewind/zero etc.
      BIO_CTRL_RESET = 1,
      # opt - are we at the eof.
      BIO_CTRL_EOF = 2,
      # opt - extra tit-bits.
      BIO_CTRL_INFO = 3,
      # man - set the 'IO' type.
      BIO_CTRL_SET = 4,
      # man - set the 'IO' type.
      BIO_CTRL_GET = 5,
      # opt - internal, used to signify change.
      BIO_CTRL_PUSH = 6,
      # opt - internal, used to signify change.
      BIO_CTRL_POP = 7,
      # man - set the 'close' on free.
      BIO_CTRL_GET_CLOSE = 8,
      # man - set the 'close' on free.
      BIO_CTRL_SET_CLOSE = 9,
      # opt - is their more data buffered.
      BIO_CTRL_PENDING = 10,
      # opt - 'flush' buffered output.
      BIO_CTRL_FLUSH = 11,
      # man - extra stuff for 'duped' BIO
      BIO_CTRL_DUP = 12,
      # opt - number of bytes still to writes
      BIO_CTRL_WPENDING = 13,
      # opt - set callback function
      BIO_CTRL_SET_CALLBACK = 14,
      # opt - set callback function
      BIO_CTRL_GET_CALLBACK = 15,
      # BIO_f_buffer special
      BIO_CTRL_PEEK = 29,
      # BIO_s_file special,
      BIO_CTRL_SET_FILENAME = 30,
      # dgram BIO stuff:
      # BIO_s_file special.
      BIO_CTRL_DGRAM_CONNECT = 31,
      # allow for an externally connected socket to be passed in.
      BIO_CTRL_DGRAM_SET_CONNECTED = 32,
      # setsockopt, essentially.
      BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33,
      # getsockopt, essentially.
      BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34,
      # setsockopt, essentially.
      BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35,
      # getsockopt, essentially
      BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36,
      # flag whether the last.
      BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37,
      # I/O operation tiemd out.
      BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38,
      # set DF bit on egress packets
      BIO_CTRL_DGRAM_MTU_DISCOVER = 39,
      # as kernel for current MTU,
      BIO_CTRL_DGRAM_QUERY_MTU = 40, BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47,
      # get cached value for MTU.
      BIO_CTRL_DGRAM_GET_MTU = 41,
      # set cached value for MTU. Want to use this if asking the kernel fails.
      BIO_CTRL_DGRAM_SET_MTU = 42,
      # check whether the MTU was exceed in the previous write operation.
      BIO_CTRL_DGRAM_MTU_EXCEEDED = 43, BIO_CTRL_DGRAM_GET_PEER = 46,
      # Destination for the data.
      BIO_CTRL_DGRAM_SET_PEER = 44,
      # Next DTLS handshake timeout to adjust socket timeouts.
      BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45, BIO_CTRL_DGRAM_SET_DONT_FRAG = 48, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49, BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE = 50,
      # SCTP stuff
      BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY = 51, BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY = 52, BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD = 53,
      BIO_CTRL_DGRAM_SCTP_GET_SNDINFO = 60, BIO_CTRL_DGRAM_SCTP_SET_SNDINFO = 61, BIO_CTRL_DGRAM_SCTP_GET_RCVINFO = 62, BIO_CTRL_DGRAM_SCTP_SET_RCVINFO = 63,
      BIO_CTRL_DGRAM_SCTP_GET_PRINFO = 64, BIO_CTRL_DGRAM_SCTP_SET_PRINFO = 65, BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN = 70,
      # Set peek mode.
      BIO_CTRL_DGRAM_SET_PEEK_MODE = 71,
      # internal BIO:
      BIO_CTRL_SET_KTLS_SEND = 72, BIO_CTRL_SET_KTLS_SEND_CTRL_MSG = 74, BIO_CTRL_CLEAR_KTLS_CTRL_MSG = 75, BIO_CTRL_GET_KTLS_SEND = 73,
      BIO_CTRL_GET_KTLS_RECV = 76, BIO_CTRL_DGRAM_SCTP_WAIT_FOR_DRY = 77, BIO_CTRL_DGRAM_SCTP_MSG_WAITING = 78,
      # BIO_f_prefix controls.
      BIO_CTRL_SET_PREFIX = 79, BIO_CTRL_SET_INDENT = 80, BIO_CTRL_GET_INDENT = 81)

# Some values are reserved until OpenSSL 3.0.0 because they were previously
# included in SSL_OP_ALL in a 1.1.x release.
@bitflag SSLOptions::UInt64 begin
    # Disable Extended master secret
    SSL_OP_NO_EXTENDED_MASTER_SECRET = 0x00000001
    # Cleanse plaintext copies of data delivered to the application
    SSL_OP_CLEANSE_PLAINTEXT = 0x00000002
    # Allow initial connection to servers that don't support RI
    SSL_OP_LEGACY_SERVER_CONNECT = 0x00000004
    SSL_OP_TLSEXT_PADDING = 0x00000010
    SSL_OP_SAFARI_ECDHE_ECDSA_BUG = 0x00000040
    SSL_OP_IGNORE_UNEXPECTED_EOF = 0x00000080
    SSL_OP_DISABLE_TLSEXT_CA_NAMES = 0x00000200
    # In TLSv1.3 allow a non-(ec)dhe based kex_mode
    SSL_OP_ALLOW_NO_DHE_KEX = 0x00000400
    # Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added in
    # OpenSSL 0.9.6d.  Usually (depending on the application protocol) the
    # workaround is not needed.  Unfortunately some broken SSL/TLS
    # implementations cannot handle it at all, which is why we include it in
    # SSL_OP_ALL. Added in 0.9.6e
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800
    # DTLS options
    SSL_OP_NO_QUERY_MTU = 0x00001000
    # Turn on Cookie Exchange (on relevant for servers)
    SSL_OP_COOKIE_EXCHANGE = 0x00002000
    # Don't use RFC4507 ticket extension
    SSL_OP_NO_TICKET = 0x00004000
    # Use Cisco's "speshul" version of DTLS_BAD_VER
    # (only with deprecated DTLSv1_client_method())
    SSL_OP_CISCO_ANYCONNECT = 0x00008000
    # As server, disallow session resumption on renegotiation
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000
    # Don't use compression even if supported
    SSL_OP_NO_COMPRESSION = 0x00020000
    # Permit unsafe legacy renegotiation
    SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00040000
    # Disable encrypt-then-mac
    SSL_OP_NO_ENCRYPT_THEN_MAC = 0x00080000
    # Enable TLSv1.3 Compatibility mode. This is on by default. A future version
    # of OpenSSL may have this disabled by default.
    SSL_OP_ENABLE_MIDDLEBOX_COMPAT = 0x00100000
    # Prioritize Chacha20Poly1305 when client does.
    # Modifies SSL_OP_CIPHER_SERVER_PREFERENCE
    SSL_OP_PRIORITIZE_CHACHA = 0x00200000
    # Set on servers to choose the cipher according to the server's preferences
    SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000
    # If set, a server will allow a client to issue a SSLv3.0 version number as
    # latest version supported in the premaster secret, even when TLSv1.0
    # (version 3.1) was announced in the client hello. Normally this is
    # forbidden to prevent version rollback attacks.
    SSL_OP_TLS_ROLLBACK_BUG = 0x00800000
    # Switches off automatic TLSv1.3 anti-replay protection for early data. This
    # is a server-side option only (no effect on the client).
    SSL_OP_NO_ANTI_REPLAY = 0x01000000
    SSL_OP_NO_SSLv3 = 0x02000000
    SSL_OP_NO_TLSv1 = 0x04000000
    SSL_OP_NO_TLSv1_2 = 0x08000000
    SSL_OP_NO_TLSv1_1 = 0x10000000
    SSL_OP_NO_TLSv1_3 = 0x20000000
    SSL_OP_NO_RENEGOTIATION = 0x40000000
    # Make server add server-hello extension from early version of cryptopro
    # draft, when GOST ciphersuite is negotiated. Required for interoperability
    # with CryptoPro CSP 3.x
    SSL_OP_CRYPTOPRO_TLSEXT_BUG = 0x80000000
end
const SSL_OP_NO_DTLSv1 = SSL_OP_NO_TLSv1
const SSL_OP_NO_DTLSv1_2 = SSL_OP_NO_TLSv1_2
const SSL_OP_NO_SSL_MASK = (SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3)
const SSL_OP_NO_DTLS_MASK = (SSL_OP_NO_DTLSv1 | SSL_OP_NO_DTLSv1_2)

"""
    # SSL_OP_ALL: various bug workarounds that should be rather harmless.
    # This used to be 0x000FFFFFL before 0.9.7.
    # This used to be 0x80000BFFU before 1.1.1.
"""
const SSL_OP_ALL = (SSL_OP_CRYPTOPRO_TLSEXT_BUG |
                    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS |
                    SSL_OP_LEGACY_SERVER_CONNECT |
                    SSL_OP_TLSEXT_PADDING |
                    SSL_OP_SAFARI_ECDHE_ECDSA_BUG)

"""
    OpenSSL init settings.
"""
@bitflag OpenSSLInitSettings::UInt32 begin
    OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = 0x00000001
    OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002
    OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004
    OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008
    OPENSSL_INIT_NO_ADD_ALL_CIPHERS = 0x00000010
    OPENSSL_INIT_NO_ADD_ALL_DIGESTS = 0x00000020
    OPENSSL_INIT_LOAD_CONFIG = 0x00000040
    OPENSSL_INIT_NO_LOAD_CONFIG = 0x00000080
    OPENSSL_INIT_ASYNC = 0x00000100
    OPENSSL_INIT_ENGINE_RDRAND = 0x00000200
    OPENSSL_INIT_ENGINE_DYNAMIC = 0x00000400
    OPENSSL_INIT_ENGINE_OPENSSL = 0x00000800
    OPENSSL_INIT_ENGINE_CRYPTODEV = 0x00001000
    OPENSSL_INIT_ENGINE_CAPI = 0x00002000
    OPENSSL_INIT_ENGINE_PADLOCK = 0x00004000
    OPENSSL_INIT_ENGINE_AFALG = 0x00008000
    OPENSSL_INIT_ATFORK = 0x00020000
    OPENSSL_INIT_NO_ATEXIT = 0x00080000
    OPENSSL_INIT_NO_LOAD_SSL_STRINGS = 0x00100000
    OPENSSL_INIT_LOAD_SSL_STRINGS = 0x00200000
end

const OPENSSL_INIT_SSL_DEFAULT = (OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS)

#
const MBSTRING_FLAG = 0x1000

@enum(MBStringFlags::Int32,
      # Utf8 encoding
      MBSTRING_UTF8 = MBSTRING_FLAG,
      # Latin1 encoding
      MBSTRING_ASC = (MBSTRING_FLAG | 1),
      # UCS2 encoding
      MBSTRING_BMP = (MBSTRING_FLAG | 2),
      # Universal string, Utf32 encoding
      MBSTRING_UNIV = (MBSTRING_FLAG | 4))

# Longest known is SHA512.
const EVP_MAX_MD_SIZE = 64
const EVP_MAX_KEY_LENGTH = 64
const EVP_MAX_IV_LENGTH = 16
const EVP_MAX_BLOCK_LENGTH = 32

# define RSA_3   0x3L
# define RSA_F4  0x10001L

"""
    OpenSSL exception.
"""
mutable struct OpenSSLException <: Exception
    OpenSSLException() = new()
end

"""
    Big number context.
"""
mutable struct BigNumContext
    bn_ctx::Ptr{Cvoid}

    function BigNumContext()
        big_num_contex = ccall((:BN_CTX_secure_new, libcrypto), Ptr{Cvoid}, ())
        if big_num_contex == C_NULL
            throw(OpenSSLException())
        end

        big_num_contex = new(big_num_contex)

        finalizer(free, big_num_contex)
        return big_num_contex
    end
end

function free(big_num_contex::BigNumContext)
    ccall((:BN_CTX_free, libcrypto), Cvoid, (BigNumContext,), big_num_contex)

    return big_num_contex.bn_ctx = C_NULL
end

"""
    Big number, multiprecision integer arithmetics.
"""
mutable struct BigNum
    bn::Ptr{Cvoid}

    function BigNum()
        big_num = ccall((:BN_new, libcrypto), Ptr{Cvoid}, ())
        if big_num == C_NULL
            throw(OpenSSLException())
        end

        big_num = new(big_num)

        finalizer(free, big_num)
        return big_num
    end

    BigNum(value::UInt8) = BigNum(UInt64(value))

    BigNum(value::UInt32) = BigNum(UInt64(value))

    function BigNum(value::UInt64)
        big_num = BigNum()
        if ccall((:BN_set_word, libcrypto), Cint, (BigNum, UInt64), big_num, value) == 0
            throw(OpenSSLException())
        end

        return big_num
    end
end

function free(big_num::BigNum)
    ccall((:BN_free, libcrypto), Cvoid, (BigNum,), big_num)

    return big_num.bn = C_NULL
end

function Base.:+(a::BigNum, b::BigNum)::BigNum
    r = BigNum()

    if ccall((:BN_add, libcrypto), Cint, (BigNum, BigNum, BigNum), r, a, b) == 0
        throw(OpenSSLException())
    end

    return r
end

function Base.:-(a::BigNum, b::BigNum)::BigNum
    r = BigNum()

    if ccall((:BN_sub, libcrypto), Cint, (BigNum, BigNum, BigNum), r, a, b) == 0
        throw(OpenSSLException())
    end

    return r
end

function Base.:*(a::BigNum, b::BigNum)::BigNum
    r = BigNum()

    c = BigNumContext()

    if ccall((:BN_mul, libcrypto), Cint, (BigNum, BigNum, BigNum, BigNumContext), r, a, b, c) == 0
        throw(OpenSSLException())
    end

    finalize(c)

    return r
end

function Base.:/(a::BigNum, b::BigNum)::BigNum
    dv = BigNum()
    rm = BigNum()

    c = BigNumContext()

    if ccall((:BN_div, libcrypto), Cint, (BigNum, BigNum, BigNum, BigNum, BigNumContext), dv, rm, a, b, c) == 0
        throw(OpenSSLException())
    end

    finalize(rm)
    finalize(c)

    return dv
end

function Base.:%(a::BigNum, b::BigNum)::BigNum
    dv = BigNum()
    rm = BigNum()

    c = BigNumContext()

    if ccall((:BN_div, libcrypto), Cint, (BigNum, BigNum, BigNum, BigNum, BigNumContext), dv, rm, a, b, c) == 0
        throw(OpenSSLException())
    end

    finalize(dv)
    finalize(c)

    return rm
end

"""
    RSA structure.
    The RSA structure consists of several BIGNUM components.
    It can contain public as well as private RSA keys:
"""
mutable struct RSA
    rsa::Ptr{Cvoid}

    function RSA()
        rsa = ccall((:RSA_new, libcrypto), Ptr{Cvoid}, ())

        rsa = new(rsa)
        finalizer(free, rsa)

        return rsa
    end
end

function free(rsa::RSA)
    ccall((:RSA_free, libcrypto), Cvoid, (RSA,), rsa)

    return rsa.rsa = C_NULL
end

const EVP_PKEY_RSA = 6 #NID_rsaEncryption
#const EVP_PKEY_DSA = 6
const RSA_F4 = 0x10001

"""
    Generate RSA key pair.
"""
function rsa_generate_key(; bits::Int32=Int32(2048))::RSA
    rsa = RSA()
    big_num = BigNum(UInt64(RSA_F4))

    if ccall((:RSA_generate_key_ex, libcrypto), Cint, (RSA, Cint, BigNum, Ptr{Cvoid}), rsa, bits, big_num, C_NULL) != 1
        throw(OpenSSLException())
    end

    return rsa
end

"""
    EVP_PKEY, EVP Public Key interface.
"""
mutable struct EvpPKey
    evp_pkey::Ptr{Cvoid}

    function EvpPKey()::EvpPKey
        evp_pkey = ccall((:EVP_PKEY_new, libcrypto), Ptr{Cvoid}, ())
        if evp_pkey == C_NULL
            throw(OpenSSLException())
        end

        evp_pkey = new(evp_pkey)
        finalizer(free, evp_pkey)

        return evp_pkey
    end

    function EvpPKey(rsa::RSA)::EvpPKey
        evp_pkey = EvpPKey()

        if ccall((:EVP_PKEY_assign, libcrypto), Cint, (EvpPKey, Cint, RSA), evp_pkey, EVP_PKEY_RSA, rsa) == 0
            throw(OpenSSLException())
        end

        rsa.rsa = C_NULL
        return evp_pkey
    end
end

function free(evp_pkey::EvpPKey)
    ccall((:EVP_PKEY_free, libcrypto), Cvoid, (EvpPKey,), evp_pkey)

    return evp_pkey.evp_pkey = C_NULL
end

"""
    EVP_CIPHER.
"""
mutable struct EVPCipher
    evp_cipher::Ptr{Cvoid}
end

"""
    Basic Block Cipher Modes:
    - ECB Electronic Code Block
    - CBC Cipher Block Chaining
    - CFB Cipher Feedback
    - OFB Output Feedback
"""

"""
    Blowfish encryption algorithm in CBC, ECB, CFB and OFB modes.
"""
EVPBlowFishCBC()::EVPCipher = EVPCipher(ccall((:EVP_bf_cbc, libcrypto), Ptr{Cvoid}, ()))

EVPBlowFishECB()::EVPCipher = EVPCipher(ccall((:EVP_bf_ecb, libcrypto), Ptr{Cvoid}, ()))

EVPBlowFishCFB()::EVPCipher = EVPCipher(ccall((:EVP_bf_cfb, libcrypto), Ptr{Cvoid}, ()))

EVPBlowFishOFB()::EVPCipher = EVPCipher(ccall((:EVP_bf_ofb, libcrypto), Ptr{Cvoid}, ()))

"""
    AES with a 128-bit key in CBC, ECB, CFB and OFB modes.
"""
EVPAES128CBC()::EVPCipher = EVPCipher(ccall((:EVP_aes_128_cbc, libcrypto), Ptr{Cvoid}, ()))

EVPAES128ECB()::EVPCipher = EVPCipher(ccall((:EVP_aes_128_ecb, libcrypto), Ptr{Cvoid}, ()))

EVPAES128CFB()::EVPCipher = EVPCipher(ccall((:EVP_aes_128_cfb, libcrypto), Ptr{Cvoid}, ()))

EVPAES128OFB()::EVPCipher = EVPCipher(ccall((:EVP_aes_128_ofb, libcrypto), Ptr{Cvoid}, ()))

"""
    Null cipher, does nothing.
"""
EVPEncNull()::EVPCipher = EVPCipher(ccall((:EVP_enc_null, libcrypto), Ptr{Cvoid}, ()))

mutable struct EVPCipherContext
    evp_cipher_ctx::Ptr{Cvoid}

    function EVPCipherContext()
        evp_cipher_ctx = ccall((:EVP_CIPHER_CTX_new, libcrypto), Ptr{Cvoid}, ())
        if evp_cipher_ctx == C_NULL
            throw(OpenSSLException())
        end

        evp_cipher_ctx = new(evp_cipher_ctx)
        finalizer(free, evp_cipher_ctx)

        return evp_cipher_ctx
    end
end

function free(evp_cipher_ctx::EVPCipherContext)
    ccall((:EVP_CIPHER_CTX_free, libcrypto), Cvoid, (EVPCipherContext,), evp_cipher_ctx)

    return evp_cipher_ctx.evp_cipher_ctx = C_NULL
end

"""
    EVP Message Digest.
"""
mutable struct EVPDigest
    evp_md::Ptr{Cvoid}
end

EVPMDNull()::EVPDigest = EVPDigest(ccall((:EVP_md_null, libcrypto), Ptr{Cvoid}, ()))

EVPMD2()::EVPDigest = EVPDigest(ccall((:EVP_md2, libcrypto), Ptr{Cvoid}, ()))

EVPMD5()::EVPDigest = EVPDigest(ccall((:EVP_md5, libcrypto), Ptr{Cvoid}, ()))

EVPSHA1()::EVPDigest = EVPDigest(ccall((:EVP_sha1, libcrypto), Ptr{Cvoid}, ()))

"""
    EVP Message Digest Context.
"""
mutable struct EVPDigestContext
    evp_md_ctx::Ptr{Cvoid}

    function EVPDigestContext()
        evp_digest_ctx = ccall((:EVP_MD_CTX_new, libcrypto), Ptr{Cvoid}, ())
        if evp_digest_ctx == C_NULL
            throw(OpenSSLException())
        end

        evp_digest_ctx = new(evp_digest_ctx)
        finalizer(free, evp_digest_ctx)

        return evp_digest_ctx
    end
end

function free(evp_digest_ctx::EVPDigestContext)
    ccall((:EVP_MD_CTX_free, libcrypto), Cvoid, (EVPDigestContext,), evp_digest_ctx)

    return evp_digest_ctx.evp_md_ctx = C_NULL
end

function digest_init(evp_digest_ctx::EVPDigestContext, evp_digest::EVPDigest)
    if ccall((:EVP_DigestInit_ex, libcrypto), Cint, (EVPDigestContext, EVPDigest, Ptr{Cvoid}), evp_digest_ctx, evp_digest, C_NULL) == 0
        throw(OpenSSLException())
    end
end

function digest_update(evp_digest_ctx::EVPDigestContext, in_data::Vector{UInt8})
    GC.@preserve in_data begin
        if ccall((:EVP_DigestUpdate, libcrypto), Cint, (EVPDigestContext, Ptr{UInt8}, Csize_t), evp_digest_ctx, pointer(in_data), length(in_data)) == 0
            throw(OpenSSLException())
        end
    end
end

function digest_final(evp_digest_ctx::EVPDigestContext)::Vector{UInt8}
    out_data = Vector{UInt8}(undef, EVP_MAX_MD_SIZE)
    out_length = Ref{UInt32}(0)

    GC.@preserve out_data out_length begin
        if ccall((:EVP_DigestFinal_ex, libcrypto), Cint, (EVPDigestContext, Ptr{UInt8}, Ptr{UInt32}), evp_digest_ctx, pointer(out_data),
                 pointer_from_objref(out_length)) == 0
            throw(OpenSSLException())
        end
    end

    resize!(out_data, out_length.x)

    return out_data
end

"""
    Computes the message digest (hash).
"""
function digest(evp_digest::EVPDigest, io::IO)
    md_ctx = EVPDigestContext()

    digest_init(md_ctx, EVPMD5())

    while !eof(io)
        available_bytes = bytesavailable(io)
        in_data = read(io, available_bytes)
        digest_update(md_ctx, in_data)
    end

    result = digest_final(md_ctx)

    finalize(md_ctx)

    return result
end

"""
    OpenSSL BIOMethod.
"""
mutable struct BIOMethod
    bio_meth::Ptr{Cvoid}

    BIOMethod(bio_meth::Ptr{Cvoid}) = new(bio_meth)

    function BIOMethod(bio_type::String)
        println("new BIOMethod $(bio_type)")
        bio_meth_index = ccall((:BIO_get_new_index, libcrypto), Cint, ())
        @show bio_meth_index

        bio_meth = ccall((:BIO_meth_new, libcrypto), Ptr{Cvoid}, (Cint, Cstring), bio_meth_index, bio_type)

        result::Cint = ccall((:BIO_meth_set_create, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), bio_meth, BIO_STREAM_CALLBACKS.x.on_bio_create_ptr)

        result = ccall((:BIO_meth_set_destroy, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), bio_meth, BIO_STREAM_CALLBACKS.x.on_bio_destroy_ptr)

        result = ccall((:BIO_meth_set_read, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), bio_meth, BIO_STREAM_CALLBACKS.x.on_bio_read_ptr)

        result = ccall((:BIO_meth_set_write, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), bio_meth, BIO_STREAM_CALLBACKS.x.on_bio_write_ptr)

        result = ccall((:BIO_meth_set_puts, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), bio_meth, BIO_STREAM_CALLBACKS.x.on_bio_puts_ptr)

        result = ccall((:BIO_meth_set_ctrl, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), bio_meth, BIO_STREAM_CALLBACKS.x.on_bio_ctrl_ptr)

        return new(bio_meth)
    end
end

"""
    Creates a file descriptor BIO method.
"""
function BIOMethod_fd()::BIOMethod
    bio_method = ccall((:BIO_s_fd, libcrypto), Ptr{Cvoid}, ())

    return BIOMethod(bio_method)
end

"""
    Creates a memory BIO method.
"""
function BIOMethod_mem()::BIOMethod
    bio_method = ccall((:BIO_s_mem, libcrypto), Ptr{Cvoid}, ())

    return BIOMethod(bio_method)
end

function free(bio_method::BIOMethod)
    ccall((:BIO_meth_free, libcrypto), Cvoid, (BIOMethod,), bio_method)

    return bio_method.bio = C_NULL
end

"""
    BIO.
"""
mutable struct BIO
    bio::Ptr{Cvoid}

    """
        Creates a BIO object using IO stream method.
        The BIO object is not registered with the finalizer.
    """
    function BIO()
        bio = ccall((:BIO_new, libcrypto), Ptr{Cvoid}, (BIOMethod,), BIO_STREAM_METHOD.x)
        if bio == C_NULL
            throw(OpenSSLException())
        end

        bio = new(bio)
        finalizer(free, bio)

        ccall((:BIO_set_data, libcrypto), Cvoid, (BIO, Ptr{Cvoid}), bio, C_NULL)

        # Mark BIO as initalized.
        ccall((:BIO_set_init, libcrypto), Cvoid, (BIO, Cint), bio, 1)

        ccall((:BIO_set_shutdown, libcrypto), Cvoid, (BIO, Cint), bio, 0)

        return bio
    end

    """
        Creates BIO for given BIOMethod.
    """
    function BIO(bio_method::BIOMethod)
        bio = ccall((:BIO_new, libcrypto), Ptr{Cvoid}, (BIOMethod,), bio_method)
        if bio == C_NULL
            throw(OpenSSLException())
        end

        bio = new(bio)
        finalizer(free, bio)

        return bio
    end
end

function free(bio::BIO)
    ccall((:BIO_free, libcrypto), Cvoid, (BIO,), bio)

    return bio.bio = C_NULL
end

clear(bio::BIO) = bio.bio

"""
    BIO write.
"""
function Base.unsafe_write(bio::BIO, out_buffer::Ptr{UInt8}, out_length::Int)
    result = ccall((:BIO_write, libcrypto), Cint, (BIO, Ptr{Cvoid}, Cint), bio, out_buffer, out_length)

    return result
end

"""
    BIO Stream callbacks.
"""

"""
    Called to initialize new BIO Stream object.
"""
function on_bio_stream_create(bio::BIO)::Cint
    # Initalize BIO.
    ccall((:BIO_set_init, libcrypto), Cvoid, (BIO, Cint), bio, 0)

    ccall((:BIO_set_data, libcrypto), Cvoid, (BIO, Cint), bio, C_NULL)

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
    BIOStream.
"""
mutable struct BIOStream <: IO
    bio::BIO
    io::Option{IO}

    BIOStream(io::IO) = new(BIO(), io)
end

function bio_stream_set_data(bio_stream::BIOStream)
    # Ensure the BIO is valid.
    if bio_stream.bio.bio == C_NULL
        throw(Base.IOError("bio stream is closed or unusable", 0))
    end

    return ccall((:BIO_set_data, libcrypto), Cvoid, (BIO, Ptr{Cvoid}), bio_stream.bio, pointer_from_objref(bio_stream))
end

function bio_stream_from_data(bio::BIO)::BIOStream
    user_data::Ptr{Cvoid} = ccall((:BIO_get_data, libcrypto), Ptr{Cvoid}, (BIO,), bio)

    bio_stream::BIOStream = unsafe_pointer_to_objref(user_data)

    return bio_stream
end

close(bio_stream::BIOStream) = free(bio_stream.bio)

"""
    SSLMethod.
    TLSv12ClientMethod.
"""
mutable struct SSLMethod
    ssl_method::Ptr{Cvoid}
end

function TLSv12ClientMethod()
    ssl_method = ccall((:TLSv1_2_client_method, libssl), Ptr{Cvoid}, ())
    return SSLMethod(ssl_method)
end

"""
    This is the global context structure which is created by a server or client once per program life-time
    and which holds mainly default values for the SSL structures which are later created for the connections.
"""
mutable struct SSLContext
    ssl_ctx::Ptr{Cvoid}

    function SSLContext(ssl_method::SSLMethod)
        ssl_ctx = ccall((:SSL_CTX_new, libssl), Ptr{Cvoid}, (SSLMethod,), ssl_method)
        if ssl_ctx == C_NULL
            throw(OpenSSLException())
        end

        ssl_context = new(ssl_ctx)
        finalizer(free, ssl_context)
        return ssl_context
    end
end

function free(ssl_context::SSLContext)
    ccall((:SSL_CTX_free, libssl), Cvoid, (SSLContext,), ssl_context)

    return ssl_context.ssl_ctx = C_NULL
end

"""
    Sets the (external) protocol behaviour of the SSL library.
"""
function ssl_set_options(ssl_context::SSLContext, options::SSLOptions)
    result = ccall((:SSL_CTX_set_options, libssl), UInt64, (SSLContext, UInt64), ssl_context, options)

    return result
end

"""
    Configures TLS ALPN (Application-Layer Protocol Negotiation).
"""
function ssl_set_alpn(ssl_context::SSLContext, protocol_list::String)::Cint
    result = ccall((:SSL_CTX_set_alpn_protos, libssl), Cint, (SSLContext, Ptr{UInt8}, UInt32), ssl_context, pointer(protocol_list), length(protocol_list))

    return result
end

"""
    SSL structure for a connection.
"""
mutable struct SSL
    ssl::Ptr{Cvoid}

    function SSL(ssl_context::SSLContext, read_bio::BIO, write_bio::BIO)::SSL
        ssl = ccall((:SSL_new, libssl), Ptr{Cvoid}, (SSLContext,), ssl_context)
        if ssl == C_NULL
            throw(OpenSSLException())
        end

        ssl = new(ssl)
        finalizer(free, ssl)

        ccall((:SSL_set_bio, libssl), Cvoid, (SSL, BIO, BIO), ssl, read_bio, write_bio)

        return ssl
    end
end

function free(ssl::SSL)
    ccall((:SSL_free, libssl), Cvoid, (SSL,), ssl)

    return ssl.ssl = C_NULL
end

function ssl_connect(ssl::SSL)
    result = ccall((:SSL_connect, libssl), Cint, (SSL,), ssl)

    ccall((:SSL_set_read_ahead, libssl), Cvoid, (SSL, Cint), ssl, Int32(1))

    return result
end

function ssl_accept(ssl::SSL)::Cint
    result = ccall((:SSL_accept, libssl), Cint, (SSL,), ssl)

    ccall((:SSL_set_read_ahead, libssl), Cvoid, (SSL, Cint), ssl, Int32(1))

    return result
end

function ssl_disconnect(ssl::SSL)
    result = ccall((:SSL_shutdown, libssl), Cint, (SSL,), ssl)
    return result
end

function get_error(ssl::SSL, ret::Cint)::Cint
    result = ccall((:SSL_get_error, libssl), Cint, (SSL, Cint), ssl, ret)
    return result
end

function get_error()::Int64
    result = ccall((:ERR_get_error, libcrypto), Int64, ())

    #err_string = Vector{UInt8}(1024)

    return result
end

"""
    ASN1_TIME.
"""
mutable struct Asn1Time
    asn1_time::Ptr{Cvoid}

    Asn1Time(asn1_time::Ptr{Cvoid}) = new(asn1_time)

    Asn1Time() = Asn1Time(0)

    Asn1Time(date_time::DateTime) = Asn1Time(Int64(floor(datetime2unix(date_time))))

    function Asn1Time(unix_time::Int64)
        asn1_time = ccall((:ASN1_TIME_set, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid}, Int64), C_NULL, unix_time)
        if asn1_time == C_NULL
            throw(OpenSSLException())
        end

        asn1_time = new(asn1_time)

        finalizer(free, asn1_time)
        return asn1_time
    end
end

function free(asn1_time::Asn1Time)
    ccall((:ASN1_STRING_free, libcrypto), Cvoid, (Asn1Time,), asn1_time)

    return asn1_time.asn1_time = C_NULL
end

function Dates.adjust(asn1_time::Asn1Time, seconds::Second)
    adj_asn1_time = ccall((:X509_gmtime_adj, libcrypto), Ptr{Cvoid}, (Asn1Time, Int64), asn1_time, seconds.value)
    if adj_asn1_time == C_NULL
        throw(OpenSSLException())
    end

    if (adj_asn1_time != asn1_time.asn1_time)
        free(asn1_time)
        asn1_time.asn1_time = adj_asn1_time
    end
end

Dates.adjust(asn1_time::Asn1Time, days::Day) = adjust(asn1_time, Second(days))

Dates.adjust(asn1_time::Asn1Time, years::Year) = adjust(asn1_time, Day(365 * years.value))

"""
    X509 Name.
"""
mutable struct X509Name
    x509_name::Ptr{Cvoid}

    X509Name(x509_name::Ptr{Cvoid}) = new(x509_name)

    function X509Name()
        x509_name = ccall((:X509_NAME_new, libcrypto), Ptr{Cvoid}, ())
        if x509_name == C_NULL
            throw(OpenSSLException())
        end

        x509_name = new(x509_name)

        finalizer(free, x509_name)
        return x509_name
    end
end

function free(x509_name::X509Name)
    ccall((:X509_NAME_free, libcrypto), Cvoid, (X509Name,), x509_name)

    return x509_name.x509_name = C_NULL
end

"""
    X509Name to string.
"""
function Base.String(x509_name::X509Name)::String
    name_ptr = ccall((:X509_NAME_oneline, libcrypto), Cstring, (X509Name, Ptr{UInt8}, Cint), x509_name, C_NULL, 0)

    str = unsafe_string(name_ptr)

    ccall((:CRYPTO_free, libcrypto), Cvoid, (Cstring,), name_ptr)

    return str
end

function add_entry(x509_name::X509Name, field::String, value::String)
    if ccall((:X509_NAME_add_entry_by_txt, libcrypto), Cint, (X509Name, Cstring, Cint, Cstring, Cint, Cint, Cint), x509_name, field, MBSTRING_ASC, value, -1,
             -1, 0) == 0
        throw(OpenSSLException())
    end

    return nothing
end

"""
    X509 Certificate.
"""
mutable struct X509Certificate
    x509::Ptr{Cvoid}

    function X509Certificate()
        x509 = ccall((:X509_new, libcrypto), Ptr{Cvoid}, ())
        if x509 == C_NULL
            throw(OpenSSLException())
        end

        return X509Certificate(x509)
    end

    function X509Certificate(x509::Ptr{Cvoid})
        x509_cert = new(x509)

        finalizer(free, x509_cert)
        return x509_cert
    end

    """
        Creates a X509 certificate from PEM string.
    """
    function X509Certificate(in_string::AbstractString)::X509Certificate
        # Create a BIO and write the PEM string.
        bio = BIO(OpenSSL.BIOMethod_mem())
        unsafe_write(bio, pointer(in_string), length(in_string))

        x509 = ccall((:PEM_read_bio_X509, libcrypto), Ptr{Cvoid}, (BIO, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), bio, C_NULL, C_NULL, C_NULL)
        if x509 == C_NULL
            throw(OpenSSLException())
        end

        x509_cert = new(x509)

        finalizer(free, x509_cert)
        return x509_cert
    end
end

function free(x509_cert::X509Certificate)
    ccall((:X509_free, libcrypto), Cvoid, (X509Certificate,), x509_cert)

    return x509_cert.x509 = C_NULL
end

function Base.write(io::IO, x509_cert::X509Certificate)
    bio_stream = OpenSSL.BIOStream(io)

    GC.@preserve bio_stream begin
        bio_stream_set_data(bio_stream)

        result = ccall((:PEM_write_bio_X509, libcrypto), Cint, (BIO, X509Certificate), bio_stream.bio, x509_cert)

        @show result
    end
end

function sign_certificate(x509_cert::X509Certificate, evp_pkey::EvpPKey)
    evp_md = ccall((:EVP_sha256, libcrypto), Ptr{Cvoid}, ())

    result = ccall((:X509_set_pubkey, libcrypto), Cint, (X509Certificate, EvpPKey), x509_cert, evp_pkey)

    result = ccall((:X509_sign, libcrypto), Cint, (X509Certificate, EvpPKey, Ptr{Cvoid}), x509_cert, evp_pkey, evp_md)

    return result = ccall((:X509_verify, libcrypto), Cint, (X509Certificate, EvpPKey), x509_cert, evp_pkey)
end

function get_subject_name(x509_cert::X509Certificate)::X509Name
    x509_name = ccall((:X509_get_subject_name, libcrypto), Ptr{Cvoid}, (X509Certificate,), x509_cert)

    # x509_name is an internal pointer and must not be freed.
    x509_name = X509Name(x509_name)

    return x509_name
end

function set_subject_name(x509_cert::X509Certificate, x509_name::X509Name)
    if ccall((:X509_set_subject_name, libcrypto), Cint, (X509Certificate, X509Name), x509_cert, x509_name) == 0
        throw(OpenSSLException())
    end
end

function get_issuer_name(x509_cert::X509Certificate)::X509Name
    x509_name = ccall((:X509_get_issuer_name, libcrypto), Ptr{Cvoid}, (X509Certificate,), x509_cert)

    # x509_name is an internal pointer and must not be freed.
    x509_name = X509Name(x509_name)

    return x509_name
end

function set_issuer_name(x509_cert::X509Certificate, x509_name::X509Name)
    if ccall((:X509_set_issuer_name, libcrypto), Cint, (X509Certificate, X509Name), x509_cert, x509_name) == 0
        throw(OpenSSLException())
    end
end

function get_time_not_before(x509_cert::X509Certificate)::Asn1Time
    asn1_time = ccall((:X509_getm_notBefore, libcrypto), Ptr{Cvoid}, (X509Certificate,), x509_cert)
    if asn1_time == C_NULL
        throw(OpenSSLException())
    end

    asn1_time = Asn1Time(asn1_time)
    return asn1_time
end

function set_time_not_before(x509_cert::X509Certificate, asn1_time::Asn1Time)
    if ccall((:X509_set1_notBefore, libcrypto), Cint, (X509Certificate, Asn1Time), x509_cert, asn1_time) == 0
        throw(OpenSSLException())
    end
end

function get_time_not_after(x509_cert::X509Certificate)::Asn1Time
    asn1_time = ccall((:X509_getm_notAfter, libcrypto), Ptr{Cvoid}, (X509Certificate,), x509_cert)
    if asn1_time == C_NULL
        throw(OpenSSLException())
    end

    asn1_time = Asn1Time(asn1_time)
    return asn1_time
end

function set_time_not_after(x509_cert::X509Certificate, asn1_time::Asn1Time)
    if ccall((:X509_set1_notAfter, libcrypto), Cint, (X509Certificate, Asn1Time), x509_cert, asn1_time) == 0
        throw(OpenSSLException())
    end
end

function Base.getproperty(x509_certificate::X509Certificate, name::Symbol)
    if name === :subject_name
        return get_subject_name(x509_certificate)
    elseif name === :issuer_name
        return get_issuer_name(x509_certificate)
    elseif name === :time_not_before
        return get_time_not_before(x509_certificate)
    elseif name === :time_not_after
        return get_time_not_after(x509_certificate)
    else # fallback to getfield
        return getfield(x509_certificate, name)
    end
end

function Base.setproperty!(x509_certificate::X509Certificate, name::Symbol, value)
    if name === :subject_name
        set_subject_name(x509_certificate, value)
    elseif name === :issuer_name
        set_issuer_name(x509_certificate, value)
    elseif name === :time_not_before
        set_time_not_before(x509_certificate, value)
    elseif name === :time_not_after
        set_time_not_after(x509_certificate, value)
    else # fallback to setfield
        setfield!(x509_certificate, name, value)
    end
end

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
        bio_read_stream = BIOStream(read_stream)
        bio_write_stream = BIOStream(write_stream)

        ssl = SSL(ssl_context, bio_read_stream.bio, bio_write_stream.bio)

        # On finalize call first clear function, to ensure BIO_free will not be called.
        finalizer(clear, bio_read_stream.bio)
        finalizer(clear, bio_write_stream.bio)

        return new(ssl, ssl_context, bio_read_stream, bio_write_stream, ReentrantLock())
    end
end

"""
    Force read operation on the stream. This will update the pending bytes.
"""
function force_read_buffer(ssl_stream::SSLStream)
    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        has_pending = ccall((:SSL_has_pending, libssl), Cint, (SSL,), ssl_stream.ssl)

        # If there is no data in the buffer, peek and force the first read.
        in_buffer = Vector{UInt8}(undef, 1)
        read_count = ccall((:SSL_peek, libssl), Cint, (SSL, Ptr{Int8}, Cint), ssl_stream.ssl, pointer(in_buffer), length(in_buffer))
    end
end

function Base.unsafe_write(ssl_stream::SSLStream, in_buffer::Ptr{UInt8}, in_length::UInt)
    write_count::Int = 0

    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        write_count = ccall((:SSL_write, libssl), Cint, (SSL, Ptr{Cvoid}, Cint), ssl_stream.ssl, in_buffer, in_length)
    end

    return write_count
end

function Sockets.connect(ssl_stream::SSLStream)
    write_count::Int = 0

    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        if ssl_connect(ssl_stream.ssl) != 1
            throw(OpenSSLException())
        end
    end
end

function Sockets.accept(ssl_stream::SSLStream)
    write_count::Int = 0

    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        if ssl_accept(ssl_stream.ssl) != 1
            throw(OpenSSLException())
        end
    end
end

"""
    Read from the SSL stream.
"""
function Base.read(ssl_stream::SSLStream, in_length::Int32)::Vector{UInt8}
    return read(ssl_stream)
end

function Base.read(ssl_stream::SSLStream)::Vector{UInt8}
    lock(ssl_stream.lock) do
        bio_read_stream = ssl_stream.bio_read_stream
        bio_write_stream = ssl_stream.bio_write_stream

        GC.@preserve bio_read_stream bio_write_stream begin
            bio_stream_set_data(bio_read_stream)
            bio_stream_set_data(bio_write_stream)

            # Force first read, that will update the pending bytes.
            force_read_buffer(ssl_stream)

            has_pending = ccall((:SSL_has_pending, libssl), Cint, (SSL,), ssl_stream.ssl)

            pending_count = ccall((:SSL_pending, libssl), Cint, (SSL,), ssl_stream.ssl)

            # Allocate read buffer and copy the data to it.
            read_buffer = Vector{UInt8}(undef, pending_count)

            if pending_count != 0
                read_count = ccall((:SSL_read, libssl), Cint, (SSL, Ptr{Int8}, Cint), ssl_stream.ssl, pointer(read_buffer), pending_count)

                resize!(read_buffer, read_count)
            end

            return read_buffer
        end
    end
end

function Base.bytesavailable(ssl_stream::SSLStream)::Cint
    force_read_buffer(ssl_stream)

    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        has_pending = ccall((:SSL_has_pending, libssl), Cint, (SSL,), ssl_stream.ssl)

        pending_count = ccall((:SSL_pending, libssl), Cint, (SSL,), ssl_stream.ssl)

        return pending_count
    end
end

function Base.eof(ssl_stream::SSLStream)::Bool
    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        force_read_buffer(ssl_stream)

        has_pending = ccall((:SSL_has_pending, libssl), Cint, (SSL,), ssl_stream.ssl)

        return has_pending == 0
    end
end

"""
    Close SSL stream.
"""
function Base.close(ssl_stream::SSLStream)
    println("Close ssl_stream")

    # Ignore the disconnect result.
    ssl_disconnect(ssl_stream.ssl)

    # SSL_free() also calls the free()ing procedures for indirectly affected items, 
    # if applicable: the buffering BIO, the read and write BIOs, 
    # cipher lists specially created for this ssl, the SSL_SESSION.
    ssl_stream.bio_read_stream.bio.bio = C_NULL
    ssl_stream.bio_write_stream.bio.bio = C_NULL

    return finalize(ssl_stream.ssl)
end
"""
    Gets the X509 certificate of the peer.
"""
function get_peer_certificate(ssl_stream::SSLStream)::Option{X509Certificate}
    x509 = ccall((:SSL_get_peer_certificate, libssl), Ptr{Cvoid}, (SSL,), ssl_stream.ssl)

    if x509 != C_NULL
        return X509Certificate(x509)
    else
        return nothing
    end
end

"""
    Crypto Init.
    Initialize OpenSSL library.
"""
mutable struct OpenSSLInit
    function OpenSSLInit()
        println("=> [OpenSSL Init]")

        opts = UInt64(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_ASYNC)
        if ccall((:OPENSSL_init_crypto, libcrypto), UInt64, (Cint, Ptr{Cvoid}), opts, C_NULL) != 1
            throw(OpenSSLException())
        end

        if ccall((:OPENSSL_init_ssl, libssl), Cint, (Cint, Ptr{Cvoid}), Cint(OPENSSL_INIT_LOAD_SSL_STRINGS), C_NULL) != 1
            throw(OpenSSLException())
        end

        return new()
    end
end

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

        return new(on_bio_create_ptr, on_bio_destroy_ptr, on_bio_read_ptr, on_bio_write_ptr, on_bio_puts_ptr, on_bio_ctrl_ptr)
    end
end

function Base.String(big_num::BigNum)
    iob = IOBuffer()
    bio_stream = BIOStream(iob)

    write(iob, "0x")

    GC.@preserve bio_stream begin
        bio_stream_set_data(bio_stream)

        if ccall((:BN_print, libcrypto), Cint, (BIO, BigNum), bio_stream.bio, big_num) == 0
            throw(OpenSSLException())
        end
    end

    seek(iob, 0)

    return String(read(iob))
end

function Base.String(asn1_time::Asn1Time)
    if asn1_time.asn1_time == C_NULL
        return "C_NULL"
    end

    iob = IOBuffer()
    bio_stream = BIOStream(iob)

    GC.@preserve bio_stream begin
        bio_stream_set_data(bio_stream)

        if ccall((:ASN1_TIME_print, libcrypto), Cint, (BIO, Asn1Time), bio_stream.bio, asn1_time) == 0
            throw(OpenSSLException())
        end
    end

    seek(iob, 0)

    return String(read(iob))
end

Base.show(io::IO, big_num::BigNum) = write(io, String(big_num))

Base.show(io::IO, asn1_time::Asn1Time) = write(io, String(asn1_time))

Base.show(io::IO, x509_name::X509Name) = write(io, String(x509_name))

function Base.show(io::IO, x509_cert::X509Certificate)
    return println(io, """X509Certificate:
                       subject_name: $(x509_cert.subject_name)
                       issuer_name: $(x509_cert.issuer_name)""")
end

const OPEN_SSL_INIT = Ref{OpenSSLInit}()
const BIO_STREAM_CALLBACKS = Ref{BIOStreamCallbacks}()
const BIO_STREAM_METHOD = Ref{BIOMethod}()

"""
    Initialize module.
"""
function __init__()
    println("$(@__MODULE__)::__init")
    OPEN_SSL_INIT.x = OpenSSLInit()
    BIO_STREAM_CALLBACKS.x = BIOStreamCallbacks()
    return BIO_STREAM_METHOD.x = BIOMethod("BIO_STREAM_METHOD")
end

end # OpenSSL module
