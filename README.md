# OpenSSL.jl 

[OpenSSL](https://www.openssl.org/) Julia bindings.

[![Build Status](https://github.com/JuliaWeb/OpenSSL.jl/workflows/CI/badge.svg)](https://github.com/JuliaWeb/OpenSSL.jl/actions?query=workflow%3ACI+branch%3Amain)
[![codecov](https://codecov.io/gh/JuliaWeb/OpenSSL.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/JuliaWeb/OpenSSL.jl)

## Installation

The package can be installed with Julia's package manager,
either by using the Pkg REPL mode (press `]` to enter):
```
pkg> add OpenSSL
```
or by using Pkg functions
```julia
julia> using Pkg; Pkg.add("OpenSSL")
```

## Project Status

The package has matured and is used in many production systems.
But as with all open-source software, please try it out and report your experience.

The package is tested against current Julia LTS (1.6), latest release (1.8), and nightly on Linux, macOS, and Windows.

## Contributing and Questions

Contributions are very welcome, as are feature requests and suggestions. Please open an
[issue][issues-url] if you encounter any problems or would just like to ask a question.

## Usage

While various parts of the openssl API are wrapped and tested, the main user-facing API expected to work
at the moment is for http TLS encryption/decryption, used like:

```julia
using OpenSSL, Sockets
# open a simple TCP connection to an https endpoint
tcp = connect("www.nghttp2.org", 443)
# wrap tcp socket in OpenSSL.SSLStream
ssl = SSLStream(tcp)
# inject host for cert verification
OpenSSL.hostname!(ssl, "www.nghttp2.org")
# perform TLS handshake
OpenSSL.connect(ssl)
# can now write/read from ssl
request_str = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"
written = write(ssl, request_str)
@test !eof(ssl)
io = IOBuffer()
sleep(2)
write(io, readavailable(ssl))
response = String(take!(io))
@test startswith(response, "HTTP/1.1 200 OK\r\n")
close(ssl)
```


[issues-url]: https://github.com/JuliaWeb/OpenSSL.jl/issues