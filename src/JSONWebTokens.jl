module JSONWebTokens

using MbedTLS
using JSON
using Base64
using HTTP
using Random

import Base: show, isvalid
export JWT, JWK, JWKRSA, JWKSymmetric, JWKSet, issigned, isverified, isvalid, validate!, sign!, show, claims, refresh!, kid

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
end
show(io::IO, jwt::JWKSet) = print(io, "JWKSet $(length(jwt.keys)) keys ($(jwt.url))")

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

claims(jwt::JWT) = decodepart(jwt.payload)
issigned(jwt::JWT) = (nothing !== jwt.signature) && (nothing !== jwt.header)
isverified(jwt::JWT) = jwt.verified
isvalid(jwt::JWT) = jwt.valid
function kid(jwt::JWT)
    @assert issigned(jwt)
    decodepart(jwt.header)["kid"]
end

show(io::IO, jwt::JWT) = print(io, issigned(jwt) ? join([jwt.header, jwt.payload, jwt.signature], '.') : jwt.payload)

validate!(jwt::JWT, keyset::JWKSet) = validate!(jwt, keyset, kid(jwt))
function validate!(jwt::JWT, keyset::JWKSet, kid::String)
    isverified(jwt) && (return isvalid(jwt))
    (kid in keys(keyset.keys)) || refresh!(keyset)
    validate!(jwt, keyset.keys[kid])
end
function validate!(jwt::JWT, key::T) where {T <: JWK}
    isverified(jwt) && return
    @assert issigned(jwt)

    data = jwt.header * "." * jwt.payload
    sigbytes = base64decode(urldec(jwt.signature))

    jwt.verified = true
    jwt.valid = (T <: JWKRSA) ? (MbedTLS.verify(key.key, key.kind, MbedTLS.digest(key.kind, data), sigbytes) == 0) : (MbedTLS.digest(key.kind, data, key.key) == sigbytes)
end

function sign!(jwt::JWT, keyset::JWKSet, kid::String)
    issigned(jwt) && return
    (kid in keys(keyset.keys)) || refresh!(keyset)
    sign!(jwt::JWT, keyset.keys[kid], kid)
end
function sign!(jwt::JWT, key::T, kid::String="") where {T <: JWK}
    issigned(jwt) && return

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

function refresh!(keyset::JWKSet, keyseturl::String)
    keyset.url = keyseturl
    refresh!(keyset)
end

function refresh!(keyset::JWKSet)
    keys = Dict{String,JWK}()
    refresh!(keyset.url, keys)
    keyset.keys = keys
    nothing
end

function refresh!(keyseturl::String, keysetdict::Dict{String,JWK})
    jstr = startswith(keyseturl, "file://") ? readchomp(keyseturl[8:end]) : String(HTTP.request("GET", keyseturl).body)
    keys = JSON.parse(jstr)["keys"]

    for key in keys
        kid = key["kid"]
        kty = key["kty"]
        alg = key["alg"]

        # ref: https://tools.ietf.org/html/rfc7518
        if kty == "RSA"
            if alg == "RS256"
                try
                    n = urldec(key["n"])
                    e = urldec(key["e"])
                    keysetdict[kid] = JWKRSA(MbedTLS.MD_SHA256, pubkey(n, e))
                catch ex
                    @warn("exception $ex trying to decode, skipping key $kid")
                end
            else
                @warn("key alg $(key["alg"]) not supported yet, skipping key $kid")
                continue
            end
        elseif kty == "oct"
            if alg == "HS256"
                k = base64decode(urldec(key["k"]))
                keysetdict[kid] = JWKSymmetric(MbedTLS.MD_SHA256, k)
            else
                @warn("key alg $(key["alg"]) not supported yet, skipping key $kid")
                continue
            end
        else
            @warn("key type $(key["kty"]) not supported yet, skipping key $kid")
            continue
        end
    end
    nothing
end

function pubkey(b64n, b64e)
    bytesn = base64decode(b64n)
    bytese = base64decode(b64e)
    n = parse(BigInt, bytes2hex(bytesn); base=16)
    e = parse(BigInt, bytes2hex(bytese); base=16)
    
    R = RSA(MbedTLS.MBEDTLS_RSA_PKCS_V15, MD_SHA256)
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

end # module JSONWebTokens
