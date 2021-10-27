module OpenSSL

using BitFlags
using Dates
using OpenSSL_jll
using Sockets

"""
    [x] Encryption, decryption
    [x] X509 extension
    [x] Free BIO
    [x] Free BIOMethod
    [x] Free on BIOStream
    [x] Close SSLContext
    [x] BIOStream method (callbacks)
    [x] Store the SSLContext (part of SSLStream)
    [ ] DSA certificates
    [ ] encryption/decryption set key length

Error handling:
    OpenSSL keeps the error messages in the thread TLS.
    After ccall to OpenSSL, before task has an oportinity to yield,
    we clear the OpenSSL error queue, and store the error messages in Julia task TLS.
"""

export TLSv12ClientMethod, TLSv12ServerMethod,
    SSLStream, BigNum, EvpPKey, RSA, DSA, Asn1Time, X509Name, StackOf, X509Certificate,
    X509Request, X509Store, X509Attribute, X509Extension, P12Object, EvpDigestContext, EvpCipherContext,
    EvpEncNull, EvpBlowFishCBC, EVPBlowFishECB, EvpBlowFishCFB, EvpBlowFishOFB, EvpAES128CBC,
    EvpAES128ECB, EvpAES128CFB, EvpAES128OFB, EvpMDNull, EvpMD2, EvpMD5, EvpSHA1, EvpDSS1,
    encrypt_init, cipher, add_extension, add_extensions, decrypt_init, digest_init, digest_update, digest_final,
    digest, random_bytes, rsa_generate_key, dsa_generate_key, add_entry, sign_certificate, sign_request, adjust,
    add_cert, unpack, eof, isreadable, iswritable, bytesavailable, read, unsafe_write, connect,
    get_peer_certificate, free, HTTP2_ALPN, UPDATE_HTTP2_ALPN, version

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
    BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45,
    # Do not fragment bit for the current socket, if possible on the platform.
    BIO_CTRL_DGRAM_SET_DONT_FRAG = 48,
    #
    BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49,
    # SCTP stuff
    BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE = 50,
    #
    BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY = 51,
    #
    BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY = 52,
    #
    BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD = 53,
    #
    BIO_CTRL_DGRAM_SCTP_GET_SNDINFO = 60,
    #
    BIO_CTRL_DGRAM_SCTP_SET_SNDINFO = 61,
    #
    BIO_CTRL_DGRAM_SCTP_GET_RCVINFO = 62,
    #
    BIO_CTRL_DGRAM_SCTP_SET_RCVINFO = 63,
    #
    BIO_CTRL_DGRAM_SCTP_GET_PRINFO = 64,
    #
    BIO_CTRL_DGRAM_SCTP_SET_PRINFO = 65,
    #
    BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN = 70,
    # Set peek mode.
    BIO_CTRL_DGRAM_SET_PEEK_MODE = 71,
    # BIO_get_ktls_send() returns 1 if the BIO is using the Kernel TLS data-path for sending.
    BIO_CTRL_GET_KTLS_SEND = 73,
    # BIO_get_ktls_recv() returns 1 if the BIO is using the Kernel TLS data-path for receiving.
    BIO_CTRL_GET_KTLS_RECV = 76,
    #
    BIO_CTRL_DGRAM_SCTP_WAIT_FOR_DRY = 77,
    #
    BIO_CTRL_DGRAM_SCTP_MSG_WAITING = 78,
    # BIO_f_prefix controls.
    # BIO_set_prefix() sets the prefix to be used for future lines of text.
    BIO_CTRL_SET_PREFIX = 79,
    # BIO_set_indent() sets the indentation to be used for future lines of text, using indent.
    BIO_CTRL_SET_INDENT = 80,
    # BIO_get_indent() gets the current indentation.
    BIO_CTRL_GET_INDENT = 81)

"""
    Classes of BIOs.
"""
# Socket, fd, connect or accept.
const BIO_TYPE_DESCRIPTOR = 0x0100
const BIO_TYPE_FILTER = 0x0200
const BIO_TYPE_SOURCE_SINK = 0x0400

"""
    BIO types.
"""
@enum(BIOType::Cint,
    #
    BIO_TYPE_NONE = 0,
    #
    BIO_TYPE_MEM = 1 | BIO_TYPE_SOURCE_SINK,
    #
    BIO_TYPE_FILE = 2 | BIO_TYPE_SOURCE_SINK,
    #
    BIO_TYPE_FD = 4 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR,
    #
    BIO_TYPE_SOCKET = 5 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR,
    #
    BIO_TYPE_NULL = 6 | BIO_TYPE_SOURCE_SINK,
    #
    BIO_TYPE_SSL = 7 | BIO_TYPE_FILTER,
    # Message digest BIO filter.
    BIO_TYPE_MD = 8 | BIO_TYPE_FILTER,
    #
    BIO_TYPE_BUFFER = 9 | BIO_TYPE_FILTER,
    # 
    BIO_TYPE_CIPHER = 10 | BIO_TYPE_FILTER,
    #
    BIO_TYPE_BASE64 = 11 | BIO_TYPE_FILTER,
    #
    BIO_TYPE_CONNECT = 12 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR,
    #
    BIO_TYPE_ACCEPT = 13 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR,
    # server proxy BIO
    BIO_TYPE_NBIO_TEST = 16 | BIO_TYPE_FILTER,
    #
    BIO_TYPE_NULL_FILTER = 17 | BIO_TYPE_FILTER,
    # Half a BIO pair.
    BIO_TYPE_BIO = 19 | BIO_TYPE_SOURCE_SINK,
    #
    BIO_TYPE_LINEBUFFER = 20 | BIO_TYPE_FILTER,
    #
    BIO_TYPE_DGRAM = 21 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR,
    #
    BIO_TYPE_ASN1 = 22 | BIO_TYPE_FILTER,
    #
    BIO_TYPE_COMP = 23 | BIO_TYPE_FILTER,
    #
    BIO_TYPE_DGRAM_SCTP = 24 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR,
    #
    BIO_TYPE_CORE_TO_PROV = 25 | BIO_TYPE_SOURCE_SINK,
    #
    BIO_TYPE_START = 128)

# Some values are reserved until OpenSSL 3.0.0 because they were previously
# included in SSL_OP_ALL in a 1.1.x release.
@bitflag SSLOptions::Culong begin
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
    # Enable TLSv1.3 Compatibility mode. This is on by default.
    # A future version of OpenSSL may have this disabled by default.
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
const SSL_OP_NO_SSL_MASK = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3
const SSL_OP_NO_DTLS_MASK = SSL_OP_NO_DTLSv1 | SSL_OP_NO_DTLSv1_2

"""
    # SSL_OP_ALL: various bug workarounds that should be rather harmless.
    # This used to be 0x000FFFFFL before 0.9.7.
    # This used to be 0x80000BFFU before 1.1.1.
"""
const SSL_OP_ALL =
    SSL_OP_CRYPTOPRO_TLSEXT_BUG |
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS |
    SSL_OP_LEGACY_SERVER_CONNECT |
    SSL_OP_TLSEXT_PADDING |
    SSL_OP_SAFARI_ECDHE_ECDSA_BUG

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

const OPENSSL_INIT_SSL_DEFAULT = OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS

"""
    TlsVersion.
"""
@enum(TlsVersion::Clong,
    TLS1_VERSION = 0x0301,
    TLS1_1_VERSION = 0x0302,
    TLS1_2_VERSION = 0x0303,
    TLS1_3_VERSION = 0x0304)

#
const MBSTRING_FLAG = 0x1000

@enum(MBStringFlags::Int32,
    # Utf8 encoding
    MBSTRING_UTF8 = MBSTRING_FLAG,
    # Latin1 encoding
    MBSTRING_ASC = MBSTRING_FLAG | 1,
    # UCS2 encoding
    MBSTRING_BMP = MBSTRING_FLAG | 2,
    # Universal string, Utf32 encoding
    MBSTRING_UNIV = MBSTRING_FLAG | 4)

# Longest known is SHA512.
const EVP_MAX_MD_SIZE = 64
const EVP_MAX_KEY_LENGTH = 64
const EVP_MAX_IV_LENGTH = 16
const EVP_MAX_BLOCK_LENGTH = 32

# define RSA_3   0x3L
# define RSA_F4  0x10001L

@enum(EvpPKeyType::Int32,
    # define NID_undef 0
    EVP_PKEY_NONE = 0,
    # define NID_rsaEncryption 6
    EVP_PKEY_RSA = 6,
    # define NID_rsa 19
    EVP_PKEY_RSA2 = 19,
    # define NID_rsassaPss 912
    EVP_PKEY_RSA_PSS = 912,
    # define NID_dsa 116
    EVP_PKEY_DSA = 116,
    # define NID_dsa_2 67
    EVP_PKEY_DSA1 = 67,
    # define NID_dsaWithSHA 66
    EVP_PKEY_DSA2 = 66,
    # define NID_dsaWithSHA1 113
    EVP_PKEY_DSA3 = 113,
    # define NID_dsaWithSHA1_2 70
    EVP_PKEY_DSA4 = 70,
    # define NID_dhKeyAgreement 28
    EVP_PKEY_DH = 28,
    # define NID_dhpublicnumber 920
    EVP_PKEY_DHX = 920,
    # define NID_X9_62_id_ecPublicKey 408
    EVP_PKEY_EC = 408,
    # define NID_sm2 1172
    EVP_PKEY_SM2 = 1172,
    # define NID_hmac 855
    EVP_PKEY_HMAC = 855,
    # define NID_cmac 894
    EVP_PKEY_CMAC = 894,
    # define NID_id_scrypt 973
    EVP_PKEY_SCRYPT = 973,
    # define NID_tls1_prf 1021
    EVP_PKEY_TLS1_PRF = 1021,
    # define NID_hkdf 1036
    EVP_PKEY_HKDF = 1036,
    # define NID_poly1305 1061
    EVP_PKEY_POLY1305 = 1061,
    # define NID_siphash 1062
    EVP_PKEY_SIPHASH = 1062,
    # define NID_X25519 1034
    EVP_PKEY_X25519 = 1034,
    # define NID_ED25519 1087
    EVP_PKEY_ED25519 = 1087,
    # define NID_X448 1035
    EVP_PKEY_X448 = 1035,
    # define NID_ED448 1088
    EVP_PKEY_ED448 = 1088)

const RSA_F4 = 0x10001

@enum(OpenSSLVersion::Int32,
    # The text variant of the version number and the release date.
    OPENSSL_VERSION = 0,
    # The compiler flags set for the compilation process.
    OPENSSL_CFLAGS = 1,
    # The date of the build process.
    OPENSSL_BUILT_ON = 2,
    # The "Configure" target of the library build.
    OPENSSL_PLATFORM = 3,
    # The "OPENSSLDIR" setting of the library build.
    OPENSSL_DIR = 4,
    # The "ENGINESDIR" setting of the library build.
    OPENSSL_ENGINES_DIR = 5,
    # The short version identifier string.
    OPENSSL_VERSION_STRING = 6,
    # The longer version identifier string
    OPENSSL_FULL_VERSION_STRING = 7,
    # The MODULESDIR setting of the library.
    OPENSSL_MODULES_DIR = 8,
    # The current OpenSSL cpu settings
    OPENSSL_CPU_INFO = 9)

@enum(SSLControlCommand::Cint,
    SSL_CTRL_SET_MIN_PROTO_VERSION = 123,
    SSL_CTRL_SET_MAX_PROTO_VERSION = 124,
    SSL_CTRL_SET_SPLIT_SEND_FRAGMENT = 125,
    SSL_CTRL_SET_MAX_PIPELINES = 126,
    SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE = 127,
    SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB = 128,
    SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129,
    SSL_CTRL_GET_MIN_PROTO_VERSION = 130,
    SSL_CTRL_GET_MAX_PROTO_VERSION = 131,
    SSL_CTRL_GET_SIGNATURE_NID = 132,
    SSL_CTRL_GET_TMP_KEY = 133,
    SSL_CTRL_GET_NEGOTIATED_GROUP = 134)

"""
    OpenSSL error.
"""
struct OpenSSLError <: Exception
    msg::AbstractString

    OpenSSLError() = new(get_error())
end

"""
    Random bytes.
"""
function random_bytes!(rand_data::Vector{UInt8})
    GC.@preserve rand_data begin
        if ccall(
            (:RAND_bytes, libcrypto),
            Cint,
            (Ptr{UInt8}, Cint),
            pointer(rand_data),
            length(rand_data)) != 1
            throw(OpenSSLError())
        end
    end
end

function random_bytes(length)
    rand_data = Vector{UInt8}(undef, length)
    random_bytes!(rand_data)

    return rand_data
end

"""
    Big number context.
"""
mutable struct BigNumContext
    bn_ctx::Ptr{Cvoid}

    function BigNumContext()
        big_num_contex = ccall(
            (:BN_CTX_secure_new, libcrypto),
            Ptr{Cvoid},
            ())
        if big_num_contex == C_NULL
            throw(OpenSSLError())
        end

        big_num_contex = new(big_num_contex)
        finalizer(free, big_num_contex)

        return big_num_contex
    end
end

function free(big_num_contex::BigNumContext)
    ccall(
        (:BN_CTX_free, libcrypto),
        Cvoid,
        (BigNumContext,),
        big_num_contex)

    big_num_contex.bn_ctx = C_NULL
    return nothing
end

"""
    Big number, multiprecision integer arithmetics.
"""
mutable struct BigNum
    bn::Ptr{Cvoid}

    function BigNum(bn::Ptr{Cvoid})
        big_num = new(bn)
        finalizer(free, big_num)

        return big_num
    end

    function BigNum()
        bn = ccall(
            (:BN_new, libcrypto),
            Ptr{Cvoid},
            ())
        if bn == C_NULL
            throw(OpenSSLError())
        end

        big_num = BigNum(bn)

        return big_num
    end

    BigNum(value::UInt8) = BigNum(UInt64(value))

    BigNum(value::UInt32) = BigNum(UInt64(value))

    function BigNum(value::UInt64)
        big_num = BigNum()
        if ccall(
            (:BN_set_word, libcrypto),
            Cint,
            (BigNum, UInt64),
            big_num, value) != 1
            throw(OpenSSLError())
        end

        return big_num
    end
end

function free(big_num::BigNum)
    ccall(
        (:BN_free, libcrypto),
        Cvoid,
        (BigNum,),
        big_num)

    big_num.bn = C_NULL
    return nothing
end

function Base.:(==)(big_num_1::BigNum, big_num_2::BigNum)
    result = ccall(
        (:BN_cmp, libcrypto),
        Cint,
        (BigNum, BigNum),
        big_num_1,
        big_num_2)

    if result == -2
        throw(OpenSSLError())
    end

    return result == 0
end

"""
    BigNum does not support up ref. Duplicate the big number instead.
"""
function up_ref(big_num::BigNum)::Ptr{Cvoid}
    big_num = ccall(
        (:BN_dup, libcrypto),
        Ptr{Cvoid},
        (BigNum,),
        big_num)
    if big_num == C_NULL
        throw(OpenSSLError())
    end

    return big_num
end

function Base.:+(a::BigNum, b::BigNum)::BigNum
    r = BigNum()

    if ccall(
        (:BN_add, libcrypto),
        Cint,
        (BigNum, BigNum, BigNum),
        r,
        a,
        b) != 1
        throw(OpenSSLError())
    end

    return r
end

function Base.:-(a::BigNum, b::BigNum)::BigNum
    r = BigNum()

    if ccall(
        (:BN_sub, libcrypto),
        Cint,
        (BigNum, BigNum, BigNum),
        r,
        a,
        b) != 1
        throw(OpenSSLError())
    end

    return r
end

function Base.:*(a::BigNum, b::BigNum)::BigNum
    r = BigNum()

    c = BigNumContext()

    if ccall(
        (:BN_mul, libcrypto),
        Cint,
        (BigNum, BigNum, BigNum, BigNumContext),
        r,
        a,
        b,
        c) != 1
        throw(OpenSSLError())
    end

    finalize(c)

    return r
end

function Base.:/(a::BigNum, b::BigNum)::BigNum
    dv = BigNum()
    rm = BigNum()

    c = BigNumContext()

    if ccall(
        (:BN_div, libcrypto),
        Cint,
        (BigNum, BigNum, BigNum, BigNum, BigNumContext),
        dv,
        rm,
        a,
        b,
        c) != 1
        throw(OpenSSLError())
    end

    finalize(rm)
    finalize(c)

    return dv
end

function Base.:%(a::BigNum, b::BigNum)::BigNum
    dv = BigNum()
    rm = BigNum()

    c = BigNumContext()

    if ccall(
        (:BN_div, libcrypto),
        Cint,
        (BigNum, BigNum, BigNum, BigNum, BigNumContext),
        dv,
        rm,
        a,
        b,
        c) != 1
        throw(OpenSSLError())
    end

    finalize(dv)
    finalize(c)

    return rm
end

"""
    EVP_CIPHER.
"""
mutable struct EvpCipher
    evp_cipher::Ptr{Cvoid}
end

EvpEncNull()::EvpCipher = EvpCipher(ccall((:EVP_enc_null, libcrypto), Ptr{Cvoid}, ()))

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
EvpBlowFishCBC()::EvpCipher = EvpCipher(ccall((:EVP_bf_cbc, libcrypto), Ptr{Cvoid}, ()))

EvpBlowFishECB()::EvpCipher = EvpCipher(ccall((:EVP_bf_ecb, libcrypto), Ptr{Cvoid}, ()))

EvpBlowFishCFB()::EvpCipher = EvpCipher(ccall((:EVP_bf_cfb, libcrypto), Ptr{Cvoid}, ()))

EvpBlowFishOFB()::EvpCipher = EvpCipher(ccall((:EVP_bf_ofb, libcrypto), Ptr{Cvoid}, ()))

"""
    AES with a 128-bit key in CBC, ECB, CFB and OFB modes.
"""
EvpAES128CBC()::EvpCipher = EvpCipher(ccall((:EVP_aes_128_cbc, libcrypto), Ptr{Cvoid}, ()))

EvpAES128ECB()::EVPCipher = EvpCipher(ccall((:EVP_aes_128_ecb, libcrypto), Ptr{Cvoid}, ()))

EvpAES128CFB()::EvpCipher = EvpCipher(ccall((:EVP_aes_128_cfb, libcrypto), Ptr{Cvoid}, ()))

EvpAES128OFB()::EvpCipher = EvpCipher(ccall((:EVP_aes_128_ofb, libcrypto), Ptr{Cvoid}, ()))

"""
    Null cipher, does nothing.
"""
EvpEncNull()::EvpCipher = EvpCipher(ccall((:EVP_enc_null, libcrypto), Ptr{Cvoid}, ()))

mutable struct EvpCipherContext
    evp_cipher_ctx::Ptr{Cvoid}

    function EvpCipherContext(evp_cipher_ctx::Ptr{Cvoid})
        evp_cipher_ctx = new(evp_cipher_ctx)
        finalizer(free, evp_cipher_ctx)

        return evp_cipher_ctx
    end

    function EvpCipherContext()
        evp_cipher_ctx = ccall(
            (:EVP_CIPHER_CTX_new, libcrypto),
            Ptr{Cvoid},
            ())
        if evp_cipher_ctx == C_NULL
            throw(OpenSSLError())
        end

        return EvpCipherContext(evp_cipher_ctx)
    end
end

function free(evp_cipher_ctx::EvpCipherContext)
    ccall(
        (:EVP_CIPHER_CTX_free, libcrypto),
        Cvoid,
        (EvpCipherContext,),
        evp_cipher_ctx)

    evp_cipher_ctx.evp_cipher_ctx = C_NULL
    return nothing
end

function decrypt_init(
    evp_cipher_ctx::EvpCipherContext,
    evp_cipher::EvpCipher,
    symetric_key::Vector{UInt8},
    init_vector::Vector{UInt8})
    # Initialize encryption context.
    GC.@preserve symetric_key init_vector begin
        if ccall(
            (:EVP_DecryptInit_ex, libcrypto),
            Cint,
            (EvpCipherContext, EvpCipher, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            evp_cipher_ctx,
            evp_cipher,
            C_NULL,
            pointer(symetric_key),
            pointer(init_vector)) != 1
            throw(OpenSSLError())
        end

        #if ccall(
        #    (:EVP_CIPHER_CTX_set_key_length, libcrypto),
        #    Cint,
        #    (EvpCipherContext, Cint),
        #    evp_cipher_ctx,
        #    length(sym_key)) != 1
        #    throw(OpenSSLError())
        #end
    end
end

function encrypt_init(
    evp_cipher_ctx::EvpCipherContext,
    evp_cipher::EvpCipher,
    symetric_key::Vector{UInt8},
    init_vector::Vector{UInt8})
    # Initialize encryption context.
    GC.@preserve symetric_key init_vector begin
        if ccall(
            (:EVP_EncryptInit_ex, libcrypto),
            Cint,
            (EvpCipherContext, EvpCipher, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            evp_cipher_ctx,
            evp_cipher,
            C_NULL,
            pointer(symetric_key),
            pointer(init_vector)) != 1
            throw(OpenSSLError())
        end
    end
end

function cipher_update(evp_cipher_ctx::EvpCipherContext, in_data::Vector{UInt8})::Vector{UInt8}
    in_length = length(in_data)

    block_size = get_block_size(evp_cipher_ctx)
    enc_length = Int((in_length + block_size - 1) / block_size * block_size)

    out_data = Vector{UInt8}(undef, enc_length)
    out_length = Ref{UInt32}(0)

    GC.@preserve in_data out_data out_length begin
        if ccall(
            (:EVP_CipherUpdate, libcrypto),
            Cint,
            (EvpCipherContext, Ptr{UInt8}, Ptr{Int32}, Ptr{UInt8}, Cint),
            evp_cipher_ctx,
            pointer(out_data),
            pointer_from_objref(out_length),
            pointer(in_data),
            in_length) != 1
            throw(OpenSSLError())
        end
    end

    resize!(out_data, out_length.x)

    return out_data
end

function cipher_final(evp_cipher_ctx::EvpCipherContext)::Vector{UInt8}
    block_size = get_block_size(evp_cipher_ctx)

    out_data = Vector{UInt8}(undef, block_size)
    out_length = Ref{Int32}(0)

    GC.@preserve out_data out_length begin
        if ccall(
            (:EVP_CipherFinal_ex, libcrypto),
            Cint,
            (EvpCipherContext, Ptr{UInt8}, Ptr{Int32}),
            evp_cipher_ctx,
            pointer(out_data),
            pointer_from_objref(out_length)) != 1
            throw(OpenSSLError())
        end
    end

    resize!(out_data, out_length.x)

    return out_data
end

function cipher(evp_cipher_ctx::EvpCipherContext, in_io::IO, out_io::IO)
    while !eof(in_io)
        available_bytes = bytesavailable(in_io)
        in_data = read(in_io, available_bytes)
        write(out_io, cipher_update(evp_cipher_ctx, in_data))
    end

    write(out_io, cipher_final(evp_cipher_ctx))

    return nothing
end

get_block_size(evp_cipher_ctx::EvpCipherContext)::Int32 = ccall(
    (:EVP_CIPHER_CTX_block_size, libcrypto),
    Int32,
    (EvpCipherContext,),
    evp_cipher_ctx)

get_key_length(evp_cipher_ctx::EvpCipherContext)::Int32 = ccall(
    (:EVP_CIPHER_CTX_key_length, libcrypto),
    Int32,
    (EvpCipherContext,),
    evp_cipher_ctx)

get_init_vector_length(evp_cipher_ctx::EvpCipherContext)::Int32 = ccall(
    (:EVP_CIPHER_CTX_iv_length, libcrypto),
    Int32,
    (EvpCipherContext,),
    evp_cipher_ctx)

function Base.getproperty(evp_cipher_ctx::EvpCipherContext, name::Symbol)
    if name === :block_size
        return get_block_size(evp_cipher_ctx)
    elseif name === :key_length
        return get_key_length(evp_cipher_ctx)
    elseif name === :init_vector_length
        return get_init_vector_length(evp_cipher_ctx)
    else
        # fallback to getfield
        return getfield(evp_cipher_ctx, name)
    end
end

"""
    EVP Message Digest.
"""
mutable struct EvpDigest
    evp_md::Ptr{Cvoid}
end

EvpMDNull()::EvpDigest = EvpDigest(ccall((:EVP_md_null, libcrypto), Ptr{Cvoid}, ()))

EvpMD2()::EvpDigest = EvpDigest(ccall((:EVP_md2, libcrypto), Ptr{Cvoid}, ()))

EvpMD5()::EvpDigest = EvpDigest(ccall((:EVP_md5, libcrypto), Ptr{Cvoid}, ()))

EvpSHA1()::EvpDigest = EvpDigest(ccall((:EVP_sha1, libcrypto), Ptr{Cvoid}, ()))

EvpSHA224()::EvpDigest = EvpDigest(ccall((:EVP_sha224, libcrypto), Ptr{Cvoid}, ()))

EvpSHA256()::EvpDigest = EvpDigest(ccall((:EVP_sha256, libcrypto), Ptr{Cvoid}, ()))

EvpSHA384()::EvpDigest = EvpDigest(ccall((:EVP_sha384, libcrypto), Ptr{Cvoid}, ()))

EvpSHA512()::EvpDigest = EvpDigest(ccall((:EVP_sha512, libcrypto), Ptr{Cvoid}, ()))

EvpDSS1()::EvpDigest = EvpDigest(ccall((:EVP_dss1, libcrypto), Ptr{Cvoid}, ()))

"""
    EVP Message Digest Context.
"""
mutable struct EvpDigestContext
    evp_md_ctx::Ptr{Cvoid}

    function EvpDigestContext()
        evp_digest_ctx = ccall(
            (:EVP_MD_CTX_new, libcrypto),
            Ptr{Cvoid},
            ())
        if evp_digest_ctx == C_NULL
            throw(OpenSSLError())
        end

        evp_digest_ctx = new(evp_digest_ctx)
        finalizer(free, evp_digest_ctx)

        return evp_digest_ctx
    end
end

function free(evp_digest_ctx::EvpDigestContext)
    ccall(
        (:EVP_MD_CTX_free, libcrypto),
        Cvoid,
        (EvpDigestContext,),
        evp_digest_ctx)

    evp_digest_ctx.evp_md_ctx = C_NULL
    return nothing
end

function digest_init(evp_digest_ctx::EvpDigestContext, evp_digest::EvpDigest)
    if ccall(
        (:EVP_DigestInit_ex, libcrypto),
        Cint,
        (EvpDigestContext, EvpDigest, Ptr{Cvoid}),
        evp_digest_ctx,
        evp_digest,
        C_NULL) != 1
        throw(OpenSSLError())
    end
end

function digest_update(evp_digest_ctx::EvpDigestContext, in_data::Vector{UInt8})
    GC.@preserve in_data begin
        if ccall(
            (:EVP_DigestUpdate, libcrypto),
            Cint,
            (EvpDigestContext, Ptr{UInt8}, Csize_t),
            evp_digest_ctx,
            pointer(in_data),
            length(in_data)) != 1
            throw(OpenSSLError())
        end
    end
end

function digest_final(evp_digest_ctx::EvpDigestContext)::Vector{UInt8}
    out_data = Vector{UInt8}(undef, EVP_MAX_MD_SIZE)
    out_length = Ref{UInt32}(0)

    GC.@preserve out_data out_length begin
        if ccall(
            (:EVP_DigestFinal_ex, libcrypto),
            Cint,
            (EvpDigestContext, Ptr{UInt8}, Ptr{UInt32}),
            evp_digest_ctx,
            pointer(out_data),
            pointer_from_objref(out_length)) != 1
            throw(OpenSSLError())
        end
    end

    resize!(out_data, out_length.x)

    return out_data
end

"""
    Computes the message digest (hash).
"""
function digest(evp_digest::EvpDigest, io::IO)
    md_ctx = EvpDigestContext()

    digest_init(md_ctx, evp_digest)

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
    RSA structure.
    The RSA structure consists of several BIGNUM components.
    It can contain public as well as private RSA keys.
"""
mutable struct RSA
    rsa::Ptr{Cvoid}

    function RSA()
        rsa = ccall(
            (:RSA_new, libcrypto),
            Ptr{Cvoid},
            ())
        if rsa == C_NULL
            throw(OpenSSLError())
        end

        rsa = new(rsa)
        finalizer(free, rsa)

        return rsa
    end
end

function free(rsa::RSA)
    ccall(
        (:RSA_free, libcrypto),
        Cvoid,
        (RSA,),
        rsa)

    rsa.rsa = C_NULL
    return nothing
end

"""
    Generate RSA key pair.
"""
function rsa_generate_key(; bits::Int32=Int32(2048))::RSA
    rsa = RSA()
    big_num = BigNum(UInt64(RSA_F4))

    if ccall(
        (:RSA_generate_key_ex, libcrypto),
        Cint,
        (RSA, Cint, BigNum, Ptr{Cvoid}),
        rsa,
        bits,
        big_num,
        C_NULL) != 1
        throw(OpenSSLError())
    end

    return rsa
end

"""
    DSA structure.
"""
mutable struct DSA
    dsa::Ptr{Cvoid}

    function DSA()
        dsa = ccall(
            (:DSA_new, libcrypto),
            Ptr{Cvoid},
            ())
        if dsa == C_NULL
            throw(OpenSSLError())
        end

        dsa = new(dsa)
        finalizer(free, dsa)

        return dsa
    end
end

function free(dsa::DSA)
    ccall(
        (:DSA_free, libcrypto),
        Cvoid,
        (DSA,),
        dsa)

    dsa.dsa = C_NULL
    return nothing
end

"""
    Generate DSA key pair.
"""
function dsa_generate_key(; bits::Int32=Int32(1024))::DSA
    dsa = DSA()

    if ccall(
        (:DSA_generate_parameters_ex, libcrypto),
        Cint,
        (DSA, Cint, Ptr{UInt8}, Cint, Ptr{Cint}, Ptr{Culong}, Ptr{Cvoid}),
        dsa,
        bits,
        C_NULL,
        1,
        C_NULL,
        C_NULL,
        C_NULL) != 1
        throw(OpenSSLError())
    end

    return dsa
end

"""
    OpenSSL BIOMethod.
"""
mutable struct BIOMethod
    bio_method::Ptr{Cvoid}

    BIOMethod(bio_method::Ptr{Cvoid}) = new(bio_method)

    function BIOMethod(bio_type::String)
        bio_method_index = ccall(
            (:BIO_get_new_index, libcrypto),
            Cint,
            ())
        if bio_method_index == -1
            throw(OpenSSLError())
        end

        bio_method = ccall(
            (:BIO_meth_new, libcrypto),
            Ptr{Cvoid},
            (Cint, Cstring),
            bio_method_index,
            bio_type)
        if bio_method == C_NULL
            throw(OpenSSLError())
        end

        bio_method = new(bio_method)
        finalizer(free, bio_method)

        if ccall(
            (:BIO_meth_set_create, libcrypto),
            Cint,
            (BIOMethod, Ptr{Cvoid}),
            bio_method,
            BIO_STREAM_CALLBACKS.x.on_bio_create_ptr) != 1
            throw(OpenSSLError())
        end

        if ccall(
            (:BIO_meth_set_destroy, libcrypto),
            Cint,
            (BIOMethod, Ptr{Cvoid}),
            bio_method,
            BIO_STREAM_CALLBACKS.x.on_bio_destroy_ptr) != 1
            throw(OpenSSLError())
        end

        if ccall(
            (:BIO_meth_set_read, libcrypto),
            Cint,
            (BIOMethod, Ptr{Cvoid}),
            bio_method,
            BIO_STREAM_CALLBACKS.x.on_bio_read_ptr) != 1
            throw(OpenSSLError())
        end

        if ccall(
            (:BIO_meth_set_write, libcrypto),
            Cint,
            (BIOMethod, Ptr{Cvoid}),
            bio_method,
            BIO_STREAM_CALLBACKS.x.on_bio_write_ptr) != 1
            throw(OpenSSLError())
        end

        if ccall(
            (:BIO_meth_set_puts, libcrypto),
            Cint,
            (BIOMethod, Ptr{Cvoid}),
            bio_method,
            BIO_STREAM_CALLBACKS.x.on_bio_puts_ptr) != 1
            throw(OpenSSLError())
        end

        if ccall(
            (:BIO_meth_set_ctrl, libcrypto),
            Cint,
            (BIOMethod, Ptr{Cvoid}),
            bio_method,
            BIO_STREAM_CALLBACKS.x.on_bio_ctrl_ptr) != 1
            throw(OpenSSLError())
        end

        return bio_method
    end
end

"""
    Creates a file descriptor BIO method.
"""
function BIOMethod_fd()::BIOMethod
    bio_method = ccall(
        (:BIO_s_fd, libcrypto),
        Ptr{Cvoid},
        ())

    return BIOMethod(bio_method)
end

"""
    Creates a memory BIO method.
"""
function BIOMethodMemory()::BIOMethod
    bio_method = ccall(
        (:BIO_s_mem, libcrypto),
        Ptr{Cvoid},
        ())

    return BIOMethod(bio_method)
end

function BIOMethodSecureMemory()::BIOMethod
    bio_method = ccall(
        (:BIO_s_secmem, libcrypto),
        Ptr{Cvoid},
        ())

    return BIOMethod(bio_method)
end

function free(bio_method::BIOMethod)
    ccall(
        (:BIO_meth_free, libcrypto),
        Cvoid,
        (BIOMethod,),
        bio_method)

    bio_method.bio_method = C_NULL
    return nothing
end

"""
    BIO.
"""
mutable struct BIO
    bio::Ptr{Cvoid}

    BIO(bio::Ptr{Cvoid}) = new(bio)

    """
        Creates a BIO object using IO stream method.
        The BIO object is not registered with the finalizer.
    """
    function BIO()
        bio = ccall(
            (:BIO_new, libcrypto),
            Ptr{Cvoid},
            (BIOMethod,),
            BIO_STREAM_METHOD.x)
        if bio == C_NULL
            throw(OpenSSLError())
        end

        bio = new(bio)
        finalizer(free, bio)

        ccall(
            (:BIO_set_data, libcrypto),
            Cvoid,
            (BIO, Ptr{Cvoid}),
            bio,
            C_NULL)

        # Mark BIO as initalized.
        ccall(
            (:BIO_set_init, libcrypto),
            Cvoid,
            (BIO, Cint),
            bio,
            1)

        ccall(
            (:BIO_set_shutdown, libcrypto),
            Cvoid,
            (BIO, Cint),
            bio,
            0)

        return bio
    end

    """
        Creates BIO for given BIOMethod.
    """
    function BIO(bio_method::BIOMethod)
        bio = ccall(
            (:BIO_new, libcrypto),
            Ptr{Cvoid},
            (BIOMethod,),
            bio_method)
        if bio == C_NULL
            throw(OpenSSLError())
        end

        bio = new(bio)
        finalizer(free, bio)

        return bio
    end
end

function free(bio::BIO)
    ccall(
        (:BIO_free, libcrypto),
        Cvoid,
        (BIO,),
        bio)

    bio.bio = C_NULL
    return nothing
end

clear(bio::BIO) = bio.bio

"""
    Returns the BIO type.
"""
function bio_type(bio::BIO)::BIOType
    bio_type = ccall(
        (:BIO_method_type, libcrypto),
        Cint,
        (BIO,),
        bio)

    return BIOType(bio_type)
end

"""
    Returns internal BIO memory.
"""
function bio_get_mem_data(bio::BIO)
    if bio_type(bio) != BIO_TYPE_MEM
        throw(ArgumentError("Expecting BIO_TYPE_MEM bio."))
    end

    # Get BIOs memory data.
    # define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)(pp))
    mem_ptr = Ref{Ptr{UInt8}}(0)
    mem_data = GC.@preserve mem_ptr begin
        result = ccall(
            (:BIO_ctrl, libcrypto),
            Clong,
            (BIO, BIOCtrl, Clong, Ptr{Ptr{Cvoid}}),
            bio,
            BIO_CTRL_INFO,
            0,
            pointer_from_objref(mem_ptr))
        if mem_ptr.x != C_NULL
            return unsafe_wrap(Vector{UInt8}, mem_ptr.x, result; own=false)
        else
            return Vector{UInt8}()
        end
    end

    return mem_data
end

"""
    BIO write.
"""
## throw error here
function Base.unsafe_write(bio::BIO, out_buffer::Ptr{UInt8}, out_length::Int)
    result = ccall(
        (:BIO_write, libcrypto),
        Cint,
        (BIO, Ptr{Cvoid}, Cint),
        bio,
        out_buffer,
        out_length)
    if result < 0
        throw(OpenSSLError())
    end
end

Base.write(bio::BIO, out_data) = return unsafe_write(bio, pointer(out_data), length(out_data))

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

close(bio_stream::BIOStream) = free(bio_stream.bio)

"""
    ASN1_TIME.
"""
mutable struct Asn1Time
    asn1_time::Ptr{Cvoid}

    Asn1Time(asn1_time::Ptr{Cvoid}) = new(asn1_time)

    Asn1Time() = Asn1Time(0)

    Asn1Time(date_time::DateTime) = Asn1Time(Int64(floor(datetime2unix(date_time))))

    function Asn1Time(unix_time::Int64)
        asn1_time = ccall(
            (:ASN1_TIME_set, libcrypto),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Int64),
            C_NULL,
            unix_time)
        if asn1_time == C_NULL
            throw(OpenSSLError())
        end

        asn1_time = new(asn1_time)
        finalizer(free, asn1_time)

        return asn1_time
    end
end

function free(asn1_time::Asn1Time)
    ccall(
        (:ASN1_STRING_free, libcrypto),
        Cvoid,
        (Asn1Time,),
        asn1_time)

    asn1_time.asn1_time = C_NULL
    return nothing
end

function Dates.adjust(asn1_time::Asn1Time, seconds::Second)
    adj_asn1_time = ccall(
        (:X509_gmtime_adj, libcrypto),
        Ptr{Cvoid},
        (Asn1Time, Int64),
        asn1_time,
        seconds.value)
    if adj_asn1_time == C_NULL
        throw(OpenSSLError())
    end

    if (adj_asn1_time != asn1_time.asn1_time)
        free(asn1_time)
        asn1_time.asn1_time = adj_asn1_time
    end
end

Dates.adjust(asn1_time::Asn1Time, days::Day) = adjust(asn1_time, Second(days))

Dates.adjust(asn1_time::Asn1Time, years::Year) = adjust(asn1_time, Day(365 * years.value))

"""
    EVP_PKEY, EVP Public Key interface.
"""
mutable struct EvpPKey
    evp_pkey::Ptr{Cvoid}

    function EvpPKey(evp_pkey::Ptr{Cvoid})::EvpPKey
        evp_pkey = new(evp_pkey)
        finalizer(free, evp_pkey)

        return evp_pkey
    end

    function EvpPKey()::EvpPKey
        evp_pkey = ccall(
            (:EVP_PKEY_new, libcrypto),
            Ptr{Cvoid},
            ())
        if evp_pkey == C_NULL
            throw(OpenSSLError())
        end

        return EvpPKey(evp_pkey)
    end

    function EvpPKey(rsa::RSA)::EvpPKey
        evp_pkey = EvpPKey()

        if ccall(
            (:EVP_PKEY_assign, libcrypto),
            Cint, (EvpPKey, Cint, RSA),
            evp_pkey,
            EVP_PKEY_RSA,
            rsa) != 1
            throw(OpenSSLError())
        end

        rsa.rsa = C_NULL
        return evp_pkey
    end

    function EvpPKey(dsa::DSA)::EvpPKey
        evp_pkey = EvpPKey()

        if ccall(
            (:EVP_PKEY_assign, libcrypto),
            Cint, (EvpPKey, Cint, DSA),
            evp_pkey,
            EVP_PKEY_DSA,
            dsa) != 1
            throw(OpenSSLError())
        end

        dsa.dsa = C_NULL
        return evp_pkey
    end

    """
        Creates a EvpPKey from PEM string.
    """
    function EvpPKey(in_string::AbstractString)::EvpPKey
        # Create a BIO and write the PEM string.
        bio = BIO(BIOMethodMemory())
        unsafe_write(bio, pointer(in_string), length(in_string))

        evp_pkey = ccall(
            (:PEM_read_bio_PrivateKey, libcrypto),
            Ptr{Cvoid},
            (BIO, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            bio,
            C_NULL,
            C_NULL,
            C_NULL)
        if evp_pkey == C_NULL
            throw(OpenSSLError())
        end

        free(bio)

        return EvpPKey(evp_pkey)
    end
end

function free(evp_pkey::EvpPKey)
    ccall(
        (:EVP_PKEY_free, libcrypto),
        Cvoid,
        (EvpPKey,),
        evp_pkey)

    evp_pkey.evp_pkey = C_NULL
    return nothing
end

function Base.:(==)(evp_pkey_1::EvpPKey, evp_pkey_2::EvpPKey)
    result = ccall(
        (:EVP_PKEY_cmp, libcrypto),
        Cint,
        (EvpPKey, EvpPKey),
        evp_pkey_1,
        evp_pkey_2)

    if result == -2
        throw(OpenSSLError())
    end

    return result == 1
end

function Base.write(io::IO, evp_pkey::EvpPKey, evp_cipher::EvpCipher=EvpCipher(C_NULL))
    bio_stream = OpenSSL.BIOStream(io)

    GC.@preserve bio_stream begin
        bio_stream_set_data(bio_stream)

        if ccall(
            (:PEM_write_bio_PrivateKey, libcrypto),
            Cint,
            (BIO, EvpPKey, EvpCipher, Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}),
            bio_stream.bio,
            evp_pkey,
            evp_cipher,
            C_NULL,
            0,
            0,
            C_NULL) != 1
            throw(OpenSSLError())
        end
    end
end

function get_key_type(evp_pkey::EvpPKey)::EvpPKeyType
    pkey_type = ccall(
        (:EVP_PKEY_base_id, libcrypto),
        EvpPKeyType,
        (EvpPKey,),
        evp_pkey)

    return pkey_type
end

function Base.getproperty(evp_pkey::EvpPKey, name::Symbol)
    if name === :key_type
        return get_key_type(evp_pkey)
    else
        # fallback to getfield
        return getfield(evp_pkey, name)
    end
end

"""
    Stack Of.
"""
mutable struct StackOf{T}
    sk::Ptr{Cvoid}

    function StackOf{T}(sk::Ptr{Cvoid}) where {T}
        stack_of = new(sk)

        finalizer(free, stack_of)
        return stack_of
    end

    function StackOf{T}() where {T}
        sk = ccall(
            (:OPENSSL_sk_new_null, libcrypto),
            Ptr{Cvoid},
            ())
        if sk == C_NULL
            throw(OpenSSLError())
        end

        return StackOf{T}(sk)
    end
end

function free(stack_of::StackOf{T}) where {T}
    ccall(
        (:OPENSSL_sk_free, libcrypto),
        Cvoid,
        (StackOf{T},),
        stack_of)

    stack_of.sk = C_NULL
    return nothing
end

function Base.push!(stack_of::StackOf{T}, element::T) where {T}
    count = ccall(
        (:OPENSSL_sk_push, libcrypto),
        Cint,
        (StackOf{T}, Ptr{Cvoid}),
        stack_of,
        up_ref(element))

    if count == 0
        throw(OpenSSLError())
    end

    return count
end

function Base.pop!(stack_of::StackOf{T}) where {T}
    ptr = ccall(
        (:OPENSSL_sk_pop, libcrypto),
        Ptr{Cvoid},
        (StackOf{T},),
        stack_of)

    return T(ptr)
end

function Base.length(stack_of::StackOf{T}) where {T}
    return ccall(
        (:OPENSSL_sk_num, libcrypto),
        Cint,
        (StackOf{T},),
        stack_of)
end

"""
    X509 Name.
"""
mutable struct X509Name
    x509_name::Ptr{Cvoid}

    function X509Name(x509_name::Ptr{Cvoid})
        x509_name = new(x509_name)
        finalizer(free, x509_name)

        return x509_name
    end

    function X509Name()
        x509_name = ccall(
            (:X509_NAME_new, libcrypto),
            Ptr{Cvoid},
            ())
        if x509_name == C_NULL
            throw(OpenSSLError())
        end

        x509_name = X509Name(x509_name)

        return x509_name
    end
end

function free(x509_name::X509Name)
    ccall(
        (:X509_NAME_free, libcrypto),
        Cvoid,
        (X509Name,),
        x509_name)

    x509_name.x509_name = C_NULL
    return nothing
end

function Base.:(==)(x509_name_1::X509Name, x509_name_2::X509Name)
    result = ccall(
        (:X509_NAME_cmp, libcrypto),
        Cint,
        (X509Name, X509Name),
        x509_name_1,
        x509_name_2)

    if result == -2
        throw(OpenSSLError())
    end

    return result == 0
end

"""
    X509Name to string.
"""
function Base.String(x509_name::X509Name)::String
    name_ptr = ccall(
        (:X509_NAME_oneline, libcrypto),
        Cstring,
        (X509Name, Ptr{UInt8}, Cint),
        x509_name,
        C_NULL,
        0)
    if name_ptr == C_NULL
        throw(OpenSSLError())
    end

    str = unsafe_string(name_ptr)

    ccall(
        (:CRYPTO_free, libcrypto),
        Cvoid,
        (Cstring,),
        name_ptr)

    return str
end

function add_entry(x509_name::X509Name, field::String, value::String)
    if ccall(
        (:X509_NAME_add_entry_by_txt, libcrypto),
        Cint,
        (X509Name, Cstring, Cint, Cstring, Cint, Cint, Cint),
        x509_name,
        field,
        MBSTRING_ASC,
        value,
        -1,
        -1,
        0) != 1
        throw(OpenSSLError())
    end

    return nothing
end

"""
    X509 Attribute.
"""
mutable struct X509Attribute
    x509_attr::Ptr{Cvoid}

    function X509Attribute(x509_attr::Ptr{Cvoid})
        x509_attr = new(x509_attr)
        finalizer(free, x509_attr)

        return x509_attr
    end

    function X509Attribute()
        x509_attr = ccall(
            (:X509_ATTRIBUTE_new, libcrypto),
            Ptr{Cvoid},
            ())
        if x509_attr == C_NULL
            throw(OpenSSLError())
        end

        x509_attr = X509Attribute(x509_attr)

        return x509_attr
    end
end

function free(x509_attr::X509Attribute)
    ccall(
        (:X509_ATTRIBUTE_free, libcrypto),
        Cvoid,
        (X509Attribute,),
        x509_attr)

    x509_attr.x509_attr = C_NULL
    return nothing
end

"""
    X509Attribute does not support up ref. Duplicate the attribute instead.
"""
function up_ref(x509_attr::X509Attribute)::Ptr{Cvoid}
    x509_attr = ccall(
        (:X509_ATTRIBUTE_dup, libcrypto),
        Ptr{Cvoid},
        (X509Attribute,),
        x509_attr)
    if x509_attr == C_NULL
        throw(OpenSSLError())
    end

    return x509_attr
end

"""
    X509_EXTENSION
"""
mutable struct X509Extension
    x509_ext::Ptr{Cvoid}

    function X509Extension(x509_ext::Ptr{Cvoid})
        x509_ext = new(x509_ext)

        finalizer(free, x509_ext)
        return x509_ext
    end

    function X509Extension(name::String, value::String)
        x509_ext = ccall(
            (:X509V3_EXT_conf, libcrypto),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Cvoid}, Cstring, Cstring),
            C_NULL,
            C_NULL,
            name,
            value)
        if x509_ext == C_NULL
            throw(OpenSSLError())
        end

        return X509Extension(x509_ext)
    end
end

function free(x509_ext::X509Extension)
    ccall(
        (:X509_EXTENSION_free, libcrypto),
        Cvoid,
        (X509Extension,),
        x509_ext)

    x509_ext.x509_ext = C_NULL
    return nothing
end

"""
    X509Extension does not support up ref. Duplicate the extension instead.
"""
function up_ref(x509_ext::X509Extension)::Ptr{Cvoid}
    x509_ext = ccall(
        (:X509_EXTENSION_dup, libcrypto),
        Ptr{Cvoid},
        (X509Extension,),
        x509_ext)
    if x509_ext == C_NULL
        throw(OpenSSLError())
    end

    return x509_ext
end

"""
    X509 Certificate.
"""
mutable struct X509Certificate
    x509::Ptr{Cvoid}

    function X509Certificate()
        x509 = ccall(
            (:X509_new, libcrypto),
            Ptr{Cvoid},
            ())
        if x509 == C_NULL
            throw(OpenSSLError())
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
        bio = BIO(BIOMethodMemory())
        unsafe_write(bio, pointer(in_string), length(in_string))

        x509 = ccall(
            (:PEM_read_bio_X509, libcrypto),
            Ptr{Cvoid},
            (BIO, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            bio,
            C_NULL,
            C_NULL,
            C_NULL)
        if x509 == C_NULL
            throw(OpenSSLError())
        end

        free(bio)

        return X509Certificate(x509)
    end
end

function free(x509_cert::X509Certificate)
    ccall(
        (:X509_free, libcrypto),
        Cvoid,
        (X509Certificate,),
        x509_cert)

    x509_cert.x509 = C_NULL
    return nothing
end

function up_ref(x509_cert::X509Certificate)::Ptr{Cvoid}
    _ = ccall(
        (:X509_up_ref, libcrypto),
        Cint,
        (X509Certificate,),
        x509_cert)

    return x509_cert.x509
end

function Base.:(==)(x509_cert_1::X509Certificate, x509_cert_2::X509Certificate)
    result = ccall(
        (:X509_cmp, libcrypto),
        Cint,
        (X509Certificate, X509Certificate),
        x509_cert_1,
        x509_cert_2)

    if result == -2
        throw(OpenSSLError())
    end

    return result == 0
end

function Base.write(io::IO, x509_cert::X509Certificate)
    bio_stream = OpenSSL.BIOStream(io)

    GC.@preserve bio_stream begin
        bio_stream_set_data(bio_stream)

        if ccall(
            (:PEM_write_bio_X509, libcrypto),
            Cint,
            (BIO, X509Certificate),
            bio_stream.bio,
            x509_cert) != 1
            throw(OpenSSLError())
        end
    end
end

function sign_certificate(x509_cert::X509Certificate, evp_pkey::EvpPKey)
    evp_md = ccall(
        (:EVP_sha256, libcrypto),
        Ptr{Cvoid},
        ())

    if ccall(
        (:X509_sign, libcrypto),
        Cint,
        (X509Certificate, EvpPKey, Ptr{Cvoid}),
        x509_cert,
        evp_pkey,
        evp_md) == 0
        throw(OpenSSLError())
    end

    if ccall(
        (:X509_verify, libcrypto),
        Cint,
        (X509Certificate, EvpPKey),
        x509_cert,
        evp_pkey) != 1
        throw(OpenSSLError())
    end
end

function add_extension(x509_cert::X509Certificate, x509_ext::X509Extension)
    if ccall(
        (:X509_add_ext, libcrypto),
        Cint,
        (X509Certificate, X509Extension, Cint),
        x509_cert,
        x509_ext,
        -1) != 1
        throw(OpenSSLError())
    end
end

function get_subject_name(x509_cert::X509Certificate)::X509Name
    x509_name = ccall(
        (:X509_get_subject_name, libcrypto),
        Ptr{Cvoid},
        (X509Certificate,),
        x509_cert)

    # Duplicate x509_name as it is an internal pointer and must not be freed.
    x509_name = ccall(
        (:X509_NAME_dup, libcrypto),
        Ptr{Cvoid},
        (Ptr{Cvoid},),
        x509_name)

    if x509_name == C_NULL
        throw(OpenSSLError())
    end

    return X509Name(x509_name)
end

function set_subject_name(x509_cert::X509Certificate, x509_name::X509Name)
    if ccall(
        (:X509_set_subject_name, libcrypto),
        Cint,
        (X509Certificate, X509Name),
        x509_cert,
        x509_name) != 1
        throw(OpenSSLError())
    end
end

function get_issuer_name(x509_cert::X509Certificate)::X509Name
    x509_name = ccall(
        (:X509_get_issuer_name, libcrypto),
        Ptr{Cvoid},
        (X509Certificate,),
        x509_cert)

    # Duplicate x509_name as it is an internal pointer and must not be freed.
    x509_name = ccall(
        (:X509_NAME_dup, libcrypto),
        Ptr{Cvoid},
        (Ptr{Cvoid},),
        x509_name)

    if x509_name == C_NULL
        throw(OpenSSLError())
    end

    return X509Name(x509_name)
end

function set_issuer_name(x509_cert::X509Certificate, x509_name::X509Name)
    if ccall(
        (:X509_set_issuer_name, libcrypto),
        Cint, (X509Certificate, X509Name),
        x509_cert,
        x509_name) != 1
        throw(OpenSSLError())
    end
end

function get_time_not_before(x509_cert::X509Certificate)::Asn1Time
    asn1_time = ccall(
        (:X509_getm_notBefore, libcrypto),
        Ptr{Cvoid},
        (X509Certificate,),
        x509_cert)
    if asn1_time == C_NULL
        throw(OpenSSLError())
    end

    asn1_time = Asn1Time(asn1_time)
    return asn1_time
end

function set_time_not_before(x509_cert::X509Certificate, asn1_time::Asn1Time)
    if ccall(
        (:X509_set1_notBefore, libcrypto),
        Cint,
        (X509Certificate, Asn1Time),
        x509_cert,
        asn1_time) != 1
        throw(OpenSSLError())
    end
end

function get_time_not_after(x509_cert::X509Certificate)::Asn1Time
    asn1_time = ccall(
        (:X509_getm_notAfter, libcrypto),
        Ptr{Cvoid},
        (X509Certificate,),
        x509_cert)
    if asn1_time == C_NULL
        throw(OpenSSLError())
    end

    asn1_time = Asn1Time(asn1_time)
    return asn1_time
end

function set_time_not_after(x509_cert::X509Certificate, asn1_time::Asn1Time)
    if ccall(
        (:X509_set1_notAfter, libcrypto),
        Cint,
        (X509Certificate, Asn1Time),
        x509_cert,
        asn1_time) != 1
        throw(OpenSSLError())
    end
end

function get_version(x509_cert::X509Certificate)::Int
    version = ccall(
        (:X509_get_version, libcrypto),
        Clong,
        (X509Certificate,),
        x509_cert)

    return Int(version)
end

function set_version(x509_cert::X509Certificate, version::Int)
    if ccall(
        (:X509_set_version, libcrypto),
        Cint,
        (X509Certificate, Cint),
        x509_cert,
        version) != 1
        throw(OpenSSLError())
    end
end

function get_public_key(x509_cert::X509Certificate)::EvpPKey
    evp_pkey = ccall(
        (:X509_get_pubkey, libcrypto),
        Ptr{Cvoid},
        (X509Certificate,),
        x509_cert)
    if evp_pkey == C_NULL
        throw(OpenSSLError())
    end

    return EvpPKey(evp_pkey)
end

function set_public_key(x509_cert::X509Certificate, evp_pkey::EvpPKey)
    if ccall(
        (:X509_set_pubkey, libcrypto),
        Cint,
        (X509Certificate, EvpPKey),
        x509_cert,
        evp_pkey) != 1
        throw(OpenSSLError())
    end
end

function Base.getproperty(x509_cert::X509Certificate, name::Symbol)
    if name === :subject_name
        return get_subject_name(x509_cert)
    elseif name === :issuer_name
        return get_issuer_name(x509_cert)
    elseif name === :time_not_before
        return get_time_not_before(x509_cert)
    elseif name === :time_not_after
        return get_time_not_after(x509_cert)
    elseif name === :version
        return get_version(x509_cert)
    elseif name === :public_key
        return get_public_key(x509_cert)
    else
        # fallback to getfield
        return getfield(x509_cert, name)
    end
end

function Base.setproperty!(x509_cert::X509Certificate, name::Symbol, value)
    if name === :subject_name
        set_subject_name(x509_cert, value)
    elseif name === :issuer_name
        set_issuer_name(x509_cert, value)
    elseif name === :time_not_before
        set_time_not_before(x509_cert, value)
    elseif name === :time_not_after
        set_time_not_after(x509_cert, value)
    elseif name === :version
        set_version(x509_cert, value)
    elseif name === :public_key
        set_public_key(x509_cert, value)
    else
        # fallback to setfield
        setfield!(x509_cert, name, value)
    end
end

"""
    X509 Request.
"""
mutable struct X509Request
    x509_req::Ptr{Cvoid}

    function X509Request()
        x509_req = ccall(
            (:X509_REQ_new, libcrypto),
            Ptr{Cvoid},
            ())
        if x509_req == C_NULL
            throw(OpenSSLError())
        end

        return X509Request(x509_req)
    end

    function X509Request(x509::Ptr{Cvoid})
        x509_req = new(x509)
        finalizer(free, x509_req)

        return x509_req
    end
end

function free(x509_req::X509Request)
    ccall(
        (:X509_REQ_free, libcrypto),
        Cvoid,
        (X509Request,),
        x509_req)

    x509_req.x509_req = C_NULL
    return nothing
end

function Base.write(io::IO, x509_req::X509Request)
    bio_stream = OpenSSL.BIOStream(io)

    GC.@preserve bio_stream begin
        bio_stream_set_data(bio_stream)

        if ccall(
            (:PEM_write_bio_X509_REQ, libcrypto),
            Cint,
            (BIO, X509Request),
            bio_stream.bio,
            x509_req) != 1
            throw(OpenSSLError())
        end
    end
end

function add_extensions(x509_req::X509Request, x509_exts::StackOf{X509Extension})
    if ccall(
        (:X509_REQ_add_extensions, libcrypto),
        Cint,
        (X509Request, StackOf{X509Extension}),
        x509_req,
        x509_exts) != 1
        throw(OpenSSLError())
    end
end

function sign_request(x509_req::X509Request, evp_pkey::EvpPKey)
    evp_md = ccall(
        (:EVP_sha256, libcrypto),
        Ptr{Cvoid},
        ())

    if ccall(
        (:X509_REQ_set_pubkey, libcrypto),
        Cint,
        (X509Request, EvpPKey),
        x509_req,
        evp_pkey) != 1
        throw(OpenSSLError())
    end

    if ccall(
        (:X509_REQ_sign, libcrypto),
        Cint, (X509Request, EvpPKey, Ptr{Cvoid}),
        x509_req,
        evp_pkey,
        evp_md) == 0
        throw(OpenSSLError())
    end

    if ccall(
        (:X509_REQ_verify, libcrypto),
        Cint, (X509Request, EvpPKey),
        x509_req,
        evp_pkey) != 1
        throw(OpenSSLError())
    end
end

function get_subject_name(x509_req::X509Request)::X509Name
    x509_name = ccall(
        (:X509_REQ_get_subject_name, libcrypto),
        Ptr{Cvoid},
        (X509Request,),
        x509_req)

    # Duplicate x509_name as it is an internal pointer and must not be freed.
    x509_name = ccall(
        (:X509_NAME_dup, libcrypto),
        Ptr{Cvoid},
        (Ptr{Cvoid},),
        x509_name)

    if x509_name == C_NULL
        throw(OpenSSLError())
    end

    return X509Name(x509_name)
end

function set_subject_name(x509_req::X509Request, x509_name::X509Name)
    if ccall(
        (:X509_REQ_set_subject_name, libcrypto),
        Cint,
        (X509Request, X509Name),
        x509_req,
        x509_name) != 1
        throw(OpenSSLError())
    end
end

function get_public_key(x509_req::X509Request)::EvpPKey
    evp_pkey = ccall(
        (:X509_REQ_get_pubkey, libcrypto),
        Ptr{Cvoid},
        (X509Request,),
        x509_req)
    if evp_pkey == C_NULL
        throw(OpenSSLError())
    end

    return EvpPKey(evp_pkey)
end

function set_public_key(x509_req::X509Request, evp_pkey::EvpPKey)
    if ccall(
        (:X509_REQ_set_pubkey, libcrypto),
        Cint,
        (X509Request, EvpPKey),
        x509_req,
        evp_pkey) != 1
        throw(OpenSSLError())
    end
end

function get_extensions(x509_req::X509Request)
    sk = ccall(
        (:X509_REQ_get_extensions, libcrypto),
        Ptr{Cvoid},
        (X509Request,),
        x509_req)
    if sk == C_NULL
        throw(OpenSSLError())
    end

    return StackOf{X509Extension}(sk)
end

function Base.getproperty(x509_req::X509Request, name::Symbol)
    if name === :subject_name
        return get_subject_name(x509_req)
    elseif name === :public_key
        return get_public_key(x509_req)
    elseif name === :extensions
        return get_extensions(x509_req)
    else
        # fallback to getfield
        return getfield(x509_req, name)
    end
end

function Base.setproperty!(x509_req::X509Request, name::Symbol, value)
    if name === :subject_name
        set_subject_name(x509_req, value)
    elseif name === :public_key
        set_public_key(x509_req, value)
    else
        # fallback to setfield
        setfield!(x509_req, name, value)
    end
end

"""
    X509 Store.
"""
mutable struct X509Store
    x509_store::Ptr{Cvoid}

    function X509Store(x509_store::Ptr{Cvoid})
        x509_store = new(x509_store)
        finalizer(free, x509_store)

        return x509_store
    end

    function X509Store()
        x509_store = ccall(
            (:X509_STORE_new, libcrypto),
            Ptr{Cvoid},
            ())
        if x509_store == C_NULL
            throw(OpenSSLError())
        end

        return X509Store(x509_store)
    end
end

function free(x509_store::X509Store)
    ccall(
        (:X509_STORE_free, libcrypto),
        Cvoid,
        (X509Store,),
        x509_store)

    x509_store.x509_store = C_NULL
    return nothing
end

function add_cert(x509_store::X509Store, x509_cert::X509Certificate)
    if ccall(
        (:X509_STORE_add_cert, libcrypto),
        Cint,
        (X509Store, X509Certificate),
        x509_store,
        x509_cert) != 1
        throw(OpenSSLError())
    end
end

"""
    PKCS12 - Public Key Cryptography Standard #12
"""
mutable struct P12Object
    pkcs12::Ptr{Cvoid}

    function P12Object()
        pkcs12 = ccall(
            (:PKCS12_new, libcrypto),
            Ptr{Cvoid},
            ())
        if pkcs12 == C_NULL
            throw(OpenSSLError())
        end

        return P12Object(pkcs12)
    end

    function P12Object(pkcs12::Ptr{Cvoid})
        p12_object = new(pkcs12)
        finalizer(free, p12_object)

        return p12_object
    end

    function P12Object(evp_pkey::EvpPKey, x509_cert::X509Certificate)
        pkcs12 = ccall(
            (:PKCS12_create, libcrypto),
            Ptr{Cvoid},
            (Cstring, Cstring, EvpPKey, X509Certificate, Ptr{Cvoid}, Cint, Cint, Cint, Cint, Cint),
            C_NULL,
            C_NULL,
            evp_pkey,
            x509_cert,
            C_NULL,
            0,
            0,
            0,
            0,
            0)
        if pkcs12 == C_NULL
            throw(OpenSSLError())
        end

        return P12Object(pkcs12)
    end
end

function free(p12_object::P12Object)
    ccall(
        (:PKCS12_free, libcrypto),
        Cvoid,
        (P12Object,),
        p12_object)

    p12_object.pkcs12 = C_NULL
    return nothing
end

function Base.write(io::IO, p12_object::P12Object)
    bio_stream = OpenSSL.BIOStream(io)

    GC.@preserve bio_stream begin
        bio_stream_set_data(bio_stream)

        if ccall(
            (:i2d_PKCS12_bio, libcrypto),
            Cint,
            (BIO, P12Object),
            bio_stream.bio,
            p12_object) != 1
            throw(OpenSSLError())
        end
    end
end

function unpack(p12_object::P12Object)
    evp_pkey::EvpPKey = EvpPKey(C_NULL)
    x509_cert::X509Certificate = X509Certificate(C_NULL)
    x509_ca_stack::StackOf{X509Certificate} = StackOf{X509Certificate}(C_NULL)

    if ccall(
        (:PKCS12_parse, libcrypto),
        Cint,
        (P12Object, Cstring, Ref{EvpPKey}, Ref{X509Certificate}, Ref{StackOf{X509Certificate}}),
        p12_object,
        C_NULL,
        evp_pkey,
        x509_cert,
        x509_ca_stack) != 1
        throw(OpenSSLError())
    end

    return evp_pkey, x509_cert, x509_ca_stack
end

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

    function SSLContext(ssl_method::SSLMethod)
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

function ssl_connect(ssl::SSL)
    if ccall(
        (:SSL_connect, libssl),
        Cint,
        (SSL,),
        ssl) != 1
        throw(OpenSSLError())
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
    if ccall(
        (:SSL_accept, libssl),
        Cint,
        (SSL,),
        ssl) != 1
        throw(OpenSSLError())
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

function get_error(ssl::SSL, ret::Cint)::Cint
    return ccall(
        (:SSL_get_error, libssl),
        Cint,
        (SSL, Cint),
        ssl,
        ret)
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
        # Create a read and write BIOs.
        bio_read::BIO = BIO()
        bio_write::BIO = BIO()

        # Create a new BIOs instances (without the finalizer), as SSL will free them on close.
        bio_read_ssl_context = BIO(bio_read.bio)
        bio_write_ssl_context = BIO(bio_write.bio)

        bio_read_stream = BIOStream(bio_read_ssl_context, read_stream)
        bio_write_stream = BIOStream(bio_write_ssl_context, write_stream)

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
    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        _ = ccall(
            (:SSL_has_pending, libssl),
            Cint,
            (SSL,),
            ssl_stream.ssl)
        update_tls_error_state()

        # If there is no data in the buffer, peek and force the first read.
        in_buffer = Vector{UInt8}(undef, 1)
        read_count = ccall(
            (:SSL_peek, libssl),
            Cint,
            (SSL, Ptr{Int8}, Cint),
            ssl_stream.ssl,
            pointer(in_buffer),
            length(in_buffer))
        if read_count <= 0
            throw(OpenSSLError())
        end
    end
end

function Base.unsafe_write(ssl_stream::SSLStream, in_buffer::Ptr{UInt8}, in_length::UInt)
    write_count::Int = 0

    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        write_count = ccall(
            (:SSL_write, libssl),
            Cint,
            (SSL, Ptr{Cvoid}, Cint),
            ssl_stream.ssl,
            in_buffer,
            in_length)
        if write_count <= 0
            throw(OpenSSLError())
        end
    end

    return write_count
end

function Sockets.connect(ssl_stream::SSLStream)
    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        ssl_connect(ssl_stream.ssl)
    end
end

function Sockets.accept(ssl_stream::SSLStream)
    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        ssl_accept(ssl_stream.ssl)
    end
end

"""
    Read from the SSL stream.
"""
Base.read(ssl_stream::SSLStream, in_length::Int32)::Vector{UInt8} = read(ssl_stream)

function Base.read(ssl_stream::SSLStream)::Vector{UInt8}
    lock(ssl_stream.lock) do
        # Force first read, that will update the pending bytes.
        force_read_buffer(ssl_stream)

        bio_read_stream = ssl_stream.bio_read_stream
        bio_write_stream = ssl_stream.bio_write_stream

        GC.@preserve bio_read_stream bio_write_stream begin
            bio_stream_set_data(bio_read_stream)
            bio_stream_set_data(bio_write_stream)

            _ = ccall(
                (:SSL_has_pending, libssl),
                Cint,
                (SSL,),
                ssl_stream.ssl)
            update_tls_error_state()

            pending_count = ccall(
                (:SSL_pending, libssl),
                Cint,
                (SSL,),
                ssl_stream.ssl)
            update_tls_error_state()

            # Allocate read buffer and copy the data to it.
            read_buffer = Vector{UInt8}(undef, pending_count)

            if pending_count != 0
                read_count = ccall(
                    (:SSL_read, libssl),
                    Cint,
                    (SSL, Ptr{Int8}, Cint),
                    ssl_stream.ssl,
                    pointer(read_buffer),
                    pending_count)
                if read_count <= 0
                    throw(OpenSSLError())
                end

                resize!(read_buffer, read_count)
            end

            return read_buffer
        end
    end
end

function Base.bytesavailable(ssl_stream::SSLStream)::Cint
    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        _ = ccall(
            (:SSL_has_pending, libssl),
            Cint,
            (SSL,),
            ssl_stream.ssl)
        update_tls_error_state()

        pending_count = ccall(
            (:SSL_pending, libssl),
            Cint,
            (SSL,),
            ssl_stream.ssl)
        update_tls_error_state()

        return pending_count
    end
end

function Base.eof(ssl_stream::SSLStream)::Bool
    bio_read_stream = ssl_stream.bio_read_stream
    bio_write_stream = ssl_stream.bio_write_stream

    # Force first read, that will update the pending bytes.
    force_read_buffer(ssl_stream)

    GC.@preserve bio_read_stream bio_write_stream begin
        bio_stream_set_data(bio_read_stream)
        bio_stream_set_data(bio_write_stream)

        has_pending = ccall(
            (:SSL_has_pending, libssl),
            Cint,
            (SSL,),
            ssl_stream.ssl)
        update_tls_error_state()

        return has_pending == 0
    end
end

Base.isreadable(ssl_stream::SSLStream)::Bool = !eof(ssl_stream) || isreadable(ssl_stream.bio_read_stream.io)

Base.iswritable(ssl_stream::SSLStream)::Bool = iswritable(ssl_stream.bio_write_stream.io)

"""
    Close SSL stream.
"""
function Base.close(ssl_stream::SSLStream)
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

"""
    Crypto Init.
    Initialize OpenSSL library.
"""
mutable struct OpenSSLInit
    function OpenSSLInit()
        println("=> [OpenSSL Init]")

        opts = UInt64(
            OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
            OPENSSL_INIT_ADD_ALL_CIPHERS |
            OPENSSL_INIT_ADD_ALL_DIGESTS |
            OPENSSL_INIT_ASYNC)

        if ccall(
            (:OPENSSL_init_crypto, libcrypto),
            UInt64,
            (Cint, Ptr{Cvoid}),
            opts,
            C_NULL) != 1
            throw(OpenSSLError())
        end

        if ccall(
            (:OPENSSL_init_ssl, libssl),
            Cint,
            (Cint, Ptr{Cvoid}),
            Cint(OPENSSL_INIT_LOAD_SSL_STRINGS),
            C_NULL) != 1
            throw(OpenSSLError())
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

        return new(
            on_bio_create_ptr,
            on_bio_destroy_ptr,
            on_bio_read_ptr,
            on_bio_write_ptr,
            on_bio_puts_ptr,
            on_bio_ctrl_ptr)
    end
end

function Base.String(big_num::BigNum)
    bio = BIO(BIOMethodMemory())

    write(bio, "0x")

    if ccall(
        (:BN_print, libcrypto),
        Cint,
        (BIO, BigNum),
        bio,
        big_num) != 1
        throw(OpenSSLError())
    end

    result = String(bio_get_mem_data(bio))

    free(bio)

    return result
end

function Base.String(asn1_time::Asn1Time)
    if asn1_time.asn1_time == C_NULL
        return "C_NULL"
    end

    bio = BIO(BIOMethodMemory())

    if ccall(
        (:ASN1_TIME_print, libcrypto),
        Cint,
        (BIO, Asn1Time),
        bio,
        asn1_time) != 1
        throw(OpenSSLError())
    end

    result = String(bio_get_mem_data(bio))

    free(bio)

    return result
end

function Base.String(x509_cert::X509Certificate)
    io = IOBuffer()

    println(io,
        """
subject_name: $(x509_cert.subject_name)
issuer_name: $(x509_cert.issuer_name)
time_not_before: $(x509_cert.time_not_before)
time_not_after: $(x509_cert.time_not_after)""")

    return String(take!(io))
end

function Base.String(x509_ext::X509Extension)
    if x509_ext.x509_ext == C_NULL
        return "C_NULL"
    end

    io = IOBuffer()

    bio = BIO(BIOMethodMemory())

    _ = ccall(
        (:X509V3_EXT_print, libcrypto),
        Cint,
        (BIO, X509Extension, Cint, Ptr{Cvoid}),
        bio,
        x509_ext,
        0,
        C_NULL)
    update_tls_error_state()

    result = String(bio_get_mem_data(bio))

    free(bio)

    return result
end

function Base.String(x509_cert::X509Request)
    io = IOBuffer()

    println(io, """subject_name: $(x509_cert.subject_name)""")

    return String(take!(io))
end

function Base.String(evp_pkey::EvpPKey)
    io = IOBuffer()

    bio = BIO(BIOMethodMemory())

    _ = ccall(
        (:EVP_PKEY_print_public, libcrypto),
        Cint,
        (BIO, EvpPKey, Cint, Ptr{Cvoid}),
        bio,
        evp_pkey,
        0,
        C_NULL)

    _ = ccall(
        (:EVP_PKEY_print_private, libcrypto),
        Cint,
        (BIO, EvpPKey, Cint, Ptr{Cvoid}),
        bio,
        evp_pkey,
        0,
        C_NULL)

    _ = ccall(
        (:EVP_PKEY_print_params, libcrypto),
        Cint,
        (BIO, EvpPKey, Cint, Ptr{Cvoid}),
        bio,
        evp_pkey,
        0,
        C_NULL)

    update_tls_error_state()

    result = String(bio_get_mem_data(bio))

    free(bio)

    return result
end

Base.show(io::IO, big_num::BigNum) = write(io, String(big_num))

Base.show(io::IO, asn1_time::Asn1Time) = write(io, String(asn1_time))

Base.show(io::IO, x509_name::X509Name) = write(io, String(x509_name))

Base.show(io::IO, x509_cert::X509Certificate) = write(io, String(x509_cert))

Base.show(io::IO, x509_ext::X509Extension) = write(io, String(x509_ext))

Base.show(io::IO, x509_req::X509Request) = write(io, String(x509_req))

Base.show(io::IO, evp_pkey::EvpPKey) = write(io, String(evp_pkey))

"""
    Error handling.
"""
function get_error()::String
    # Create memory BIO
    bio = BIO(BIOMethodMemory())

    local error_msg::String

    # Check existing error messages stored in task TLS.
    if haskey(task_local_storage(), :openssl_err)
        # Copy existing error from task TLS.
        tls_msg = task_local_storage(:openssl_err)
        delete!(task_local_storage(), :openssl_err)

        # Clear the error queue, print the error messages to the memory BIO.
        ccall(
            (:ERR_print_errors, libcrypto),
            Cvoid,
            (BIO,),
            bio)

        bio_msg = String(bio_get_mem_data(bio))
        error_msg = "$(tls_msg) : $(bio_msg)"
    else
        # Clear the error queue, print the error messages to the memory BIO.
        ccall(
            (:ERR_print_errors, libcrypto),
            Cvoid,
            (BIO,),
            bio)

        error_msg = String(bio_get_mem_data(bio))
    end

    # Read the formatted error messages from the memory BIO.

    # Ensure the queue is clear (if ERR_print_errors fails).
    ccall(
        (:ERR_clear_error, libcrypto),
        Cvoid,
        ())

    # Free bio.
    free(bio)

    return error_msg
end

"""
    Copy and clear OpenSSL error queue to the task TLS .
"""
function update_tls_error_state()
    # Check if there are errors in OpenSSL error queue.
    if ccall(
        (:ERR_peek_error, libcrypto),
        Culong,
        ()) != 0
        # Clear OpenSSL queue and store the errors in the Task TLS.
        error_str = get_error()
        task_local_storage(:openssl_err, error_str)
    end
end

function version(; version_type::OpenSSLVersion=OPENSSL_VERSION)::String
    version = ccall(
        (:OpenSSL_version, libcrypto),
        Cstring,
        (Cint,),
        version_type)

    return unsafe_string(version)
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
