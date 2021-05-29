using Documenter
using OpenSSL

makedocs(; sitename="OpenSSL", format=Documenter.HTML(), modules=[OpenSSL])

# Documenter can also automatically deploy documentation to gh-pages.
# See "Hosting Documentation" and deploydocs() in the Documenter manual
# for more information.
#=deploydocs(
    repo = "<repository url>"
)=#
