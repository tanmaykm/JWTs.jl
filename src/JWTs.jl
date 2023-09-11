module JWTs

using MbedTLS
using JSON
using Base64
using Downloads
using Random

import Base: show, isvalid
export JWT, JWK, JWKRSA, JWKSymmetric, JWKSet
export issigned, isverified, isvalid
export validate!, sign!, refresh!
export show, claims, kid
export with_valid_jwt

struct JWKSymmetric
    kind::MbedTLS.MDKind
    key::Vector{UInt8}
end

struct JWKRSA
    kind::MbedTLS.MDKind
    key::Union{RSA,MbedTLS.PKContext}
end

"""
JWK represents a JWK Key (either for signing or verification).

JWK can be either a JWKRSA or JWKSymmetric. A RSA key can
represent either the public or private key.
"""
const JWK = Union{JWKRSA,JWKSymmetric}

"""
JWKSet holds a set of keys, fetched from a OpenId key URL, each key identified by a key id.

The key URL can either be of `http(s)://` or `file://` type.
"""
mutable struct JWKSet
    url::String
    keys::Dict{String,JWK}

    function JWKSet(url::String)
        new(url, Dict{String,JWK}())
    end

    function JWKSet(keyset::Vector)
        keysetdict = Dict{String,JWK}()
        refresh!(keyset, keysetdict)
        new("", keysetdict)
    end
end
function show(io::IO, jwk::JWKSet)
    print(io, "JWKSet $(length(jwk.keys)) keys")
    isempty(jwk.url) || print(io, " ($(jwk.url))")
end

"""
JWT represents a JWT payload at the minimum.

When signed, it holds the header and signature too.
The parts are stored in encoded form.
"""
mutable struct JWT
    payload::String
    header::Union{Nothing,String}
    signature::Union{Nothing,String}
    verified::Bool
    valid::Union{Nothing,Bool}

    function JWT(; jwt::Union{Nothing,String}=nothing, payload::Union{Nothing,Dict{String,Any},String}=nothing)
        if jwt !== nothing
            @assert payload === nothing
            parts = split(jwt, ".")
            if length(parts) == 3
                new(parts[2], parts[1], parts[3], false, nothing)
            else
                new("", nothing, nothing, true, false)
            end
        else
            @assert payload !== nothing
            new(isa(payload, String) ? payload : urlenc(base64encode(JSON.json(payload))), nothing, nothing, false, nothing)
        end
    end
end

decodepart(encoded::String) = JSON.parse(String(base64decode(urldec(encoded))))

"""
    claims(jwt::JWT)

Get the claims from the JWT payload.
"""
claims(jwt::JWT) = decodepart(jwt.payload)

"""
    issigned(jwt::JWT)

Check if the JWT is signed. Does not check if the JWT is valid.    
Returns `true` if the JWT is signed, `false` otherwise.
"""
issigned(jwt::JWT) = (nothing !== jwt.signature) && (nothing !== jwt.header)

isverified(jwt::JWT) = jwt.verified
isvalid(jwt::JWT) = jwt.valid

"""
    kid(jwt::JWT)

Get the key id from the JWT header. The JWT must be signed. An `AssertionError` is thrown otherwise.
"""
function kid(jwt::JWT)
    @assert issigned(jwt)
    decodepart(jwt.header)["kid"]
end

show(io::IO, jwt::JWT) = print(io, issigned(jwt) ? join([jwt.header, jwt.payload, jwt.signature], '.') : jwt.payload)

"""
    validate!(jwt, keyset)

Validate the JWT using the keys in the keyset.
The JWT must be signed. An `AssertionError` is thrown otherwise.
The keyset must contain the key id from the JWT header. A KeyError is thrown otherwise.

Returns `true` if the JWT is valid, `false` otherwise.
"""
validate!(jwt::JWT, keyset::JWKSet) = validate!(jwt, keyset, kid(jwt))
function validate!(jwt::JWT, keyset::JWKSet, kid::String)
    isverified(jwt) && (return isvalid(jwt))
    (kid in keys(keyset.keys)) || refresh!(keyset)
    validate!(jwt, keyset.keys[kid])
end
function validate!(jwt::JWT, key::T) where {T <: JWK}
    isverified(jwt) && (return isvalid(jwt))
    @assert issigned(jwt)

    data = jwt.header * "." * jwt.payload
    sigbytes = base64decode(urldec(jwt.signature))

    jwt.verified = true

    jwt.valid = if T <: JWKRSA
        try
            MbedTLS.verify(key.key, key.kind, MbedTLS.digest(key.kind, data), sigbytes) == 0
        catch
            false
        end
    else
        MbedTLS.digest(key.kind, data, key.key) == sigbytes
    end
end

"""
    sign!(jwt, keyset, kid)

Sign the JWT using the keys in the keyset. The key id and key algorithm is included in the JWT header.
Updates the jwt with the header and signature.
Returns `nothing`.

Arguments:
- `jwt`: The JWT to sign. If the JWT is already signed, it is not signed again.
- `keyset`: The JWKSet to use for signing. Only keys in this keyset are used for signing.
- `kid`: The key id to use for signing. The keyset must contain the key id from the JWT header. A KeyError is thrown otherwise.
"""
function sign!(jwt::JWT, keyset::JWKSet, kid::String)
    issigned(jwt) && return
    (kid in keys(keyset.keys)) || refresh!(keyset)
    sign!(jwt::JWT, keyset.keys[kid], kid)
end

"""
    sign!(jwt, key, kid)

Sign the JWT using the key. The key id and key algorithm is included in the JWT header.
Updates the jwt with the header and signature.
Returns `nothing`.

Arguments:
- `jwt`: The JWT to sign. If the JWT is already signed, it is not signed again.
- `key`: The JWK to use for signing.
- `kid`: The key id to include in the JWT header.
"""
function sign!(jwt::JWT, key::T, kid::String="") where {T <: JWK}
    issigned(jwt) && return

    if T <: JWKRSA
        if key.kind === MbedTLS.MD_SHA256
            alg = "RS256"
        elseif key.kind === MbedTLS.MD_SHA384
            alg = "RS384"
        elseif key.kind === MbedTLS.MD_SHA
            alg = "RS512"
        else
            error("unsupported key algorithm")
        end
    else
        if key.kind === MbedTLS.MD_SHA256
            alg = "HS256"
        elseif key.kind === MbedTLS.MD_SHA384
            alg = "HS384"
        elseif key.kind === MbedTLS.MD_SHA
            alg = "HS512"
        else
            error("unsupported key algorithm")
        end
    end
    alg = (T <: JWKRSA) ? "RS256" : "HS256"
    header_dict = Dict{String,String}("alg"=>alg, "typ"=>"JWT")
    isempty(kid) || (header_dict["kid"] = kid)
    header = urlenc(base64encode(JSON.json(header_dict)))

    data = header * "." * jwt.payload
    sigbytes = (T <: JWKRSA) ?  MbedTLS.sign(key.key, key.kind, MbedTLS.digest(key.kind, data), MersenneTwister(0)) : MbedTLS.digest(key.kind, data, key.key)
    signature = urlenc(base64encode(sigbytes))

    jwt.header = header
    jwt.signature = signature
    jwt.verified = true
    jwt.valid = true
    nothing
end

"""
    refresh!(keyset, keyseturl; default_algs)
    refresh!(keyset; default_algs)

Arguments:
- `keyset`: The JWKSet to refresh.
- `keyseturl`: The URL to fetch the keys from.

Keyword arguments:
- `default_algs`: A dictionary of default algorithms to use for each key type.

Refresh the keyset with the keys from the keyseturl. The keyseturl can either be of `http(s)://` or `file://` type.
The keyset is updated with the keys from the keyseturl, old keys are removed.

If the keyseturl is not specified, the keyset is refreshed with the keys from the keyseturl already set in the keyset.

The default algorithm values are referred to only if the keyset does not specify the exact algorithm type.
E.g. if only "RSA" is specified as the algorithm, "RS256" will be assumed.
"""
function refresh!(keyset::JWKSet, keyseturl::String; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"))
    keyset.url = keyseturl
    refresh!(keyset; default_algs=default_algs)
end

function refresh!(keyset::JWKSet; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"))
    if !isempty(keyset.url)
        keys = Dict{String,JWK}()
        refresh!(keyset.url, keys; default_algs=default_algs)
        keyset.keys = keys
    end
    nothing
end

function refresh!(keyseturl::String, keysetdict::Dict{String,JWK}; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"))
    if startswith(keyseturl, "file://")
        jstr = readchomp(keyseturl[8:end])
    else
        output = PipeBuffer()
        Downloads.request(keyseturl; method="GET", output=output)
        jstr = String(take!(output))
    end
    keys = JSON.parse(jstr)["keys"]
    refresh!(keys, keysetdict; default_algs=default_algs)
end

function refresh!(keys::Vector, keysetdict::Dict{String,JWK}; default_algs = Dict("RSA" => "RS256", "oct" => "HS256"))
    for key in keys
        kid = key["kid"]
        kty = key["kty"]
        alg = get(key, "alg", get(default_algs, kty, "none"))

        # ref: https://tools.ietf.org/html/rfc7518
        try
            if kty == "RSA"
                n = base64decode(urldec(key["n"]))
                e = base64decode(urldec(key["e"]))
                if alg == "RS256"
                    keysetdict[kid] = JWKRSA(MbedTLS.MD_SHA256, pubkey(n, e, MbedTLS.MD_SHA256))
                elseif alg == "RS384"
                    keysetdict[kid] = JWKRSA(MbedTLS.MD_SHA384, pubkey(n, e, MbedTLS.MD_SHA384))
                elseif alg == "RS512"
                    keysetdict[kid] = JWKRSA(MbedTLS.MD_SHA, pubkey(n, e, MbedTLS.MD_SHA))
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            elseif kty == "oct"
                k = base64decode(urldec(key["k"]))
                if alg == "HS256"
                    keysetdict[kid] = JWKSymmetric(MbedTLS.MD_SHA256, k)
                elseif alg == "HS384"
                    keysetdict[kid] = JWKSymmetric(MbedTLS.MD_SHA384, k)
                elseif alg == "HS512"
                    keysetdict[kid] = JWKSymmetric(MbedTLS.MD_SHA, k)
                else
                    @warn("key alg $alg not supported yet, skipping key $kid")
                    continue
                end
            else
                @warn("key type $kty not supported yet, skipping key $kid")
                continue
            end
        catch ex
            @warn("exception $ex trying to decode, skipping key $kid")
        end
    end
    nothing
end

function pubkey(bytesn, bytese, halg)
    n = parse(BigInt, bytes2hex(bytesn); base=16)
    e = parse(BigInt, bytes2hex(bytese); base=16)

    R = RSA(MbedTLS.MBEDTLS_RSA_PKCS_V15, halg)
    MbedTLS.pubkey_from_vals!(R, e, n)
end

function urldec(bs)
    bs = replace(bs, "-"=>"+")
    bs = replace(bs, "_"=>"/")
    padb64(bs)
end

function urlenc(bs)
    bs = replace(bs, "+"=>"-")
    bs = replace(bs, "/"=>"_")
    bs = replace(bs, "="=>"")
    bs
end

function padb64(bs)
    surplus = length(bs) % 4
    if surplus > 0
        bs = bs * "="^(4 - surplus)
    end
    bs
end

"""
    with_valid_jwt(f, jwt, keyset; kid=nothing)

Run `f` with a valid JWT. The validated JWT is passed as an argument to `f`. If the JWT is invalid, an `ArgumentError` is thrown.

Arguments:
- `f`: The function to execute with a valid JWT. The validated JWT is passed as an argument to `f`.
- `jwt`: The JWT string or JWT object to use.
- `keyset`: The JWKSet to use for validation. Only keys in this keyset are used for validation.

Keyword arguments:
- `kid`: The key id to use for validation. If not specified, the `kid` from the JWT header is used.
"""
with_valid_jwt(f::Function, jwt::String, keyset::JWKSet; kid::Union{Nothing,String}=nothing) = with_valid_jwt(f, JWT(jwt), keyset; kid=kid)
function with_valid_jwt(f::Function, jwt::JWT, keyset::JWKSet; kid::Union{Nothing,String}=nothing)
    if isnothing(kid)
        validate!(jwt, keyset)
    else
        validate!(jwt, keyset, kid)
    end

    isvalid(jwt) || throw(ArgumentError("invalid jwt"))

    return f(jwt)
end

end # module JWTs
