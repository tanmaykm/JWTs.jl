using JWTs
using Test
using JSON
using MbedTLS

const test_payload_data = [
    JSON.parse("""{
        "jti": "0b821616-0a5f-47f3-af00-8caf03619303",
        "exp": 1543351759,
        "nbf": 0,
        "iat": 1543315759,
        "iss": "https://example.com/auth/",
        "aud": "portal",
        "sub": "b1df5448-a16b-4a13-b03b-2213d56ea1b5",
        "typ": "Bearer",
        "azp": "portal",
        "auth_time": 1543315759,
        "session_state": "f196425d-226b-4e6d-bc81-feecb276f424",
        "acr": "1",
        "allowed-origins": [ "" ],
        "realm_access": { "roles": [ "uma_authorization" ] },
        "resource_access": {
            "broker": { "roles": [ "read-token" ] },
            "account": { "roles": [ "manage-account", "manage-account-links", "view-profile" ] }
        },
        "preferred_username": "chhhhhhhhhhhhhhhhhhhhhhhhhaaaaaaaaaaaaabbb"
    }"""),
    JSON.parse("""{
        "iss": "https://auth2.juliacomputing.io/dex",
        "sub": "ChUxjfgsajfurjsjdut0483672kdhgstgy283jssZQ",
        "aud": "example-audience",
        "exp": 1536080651,
        "iat": 1535994251,
        "nonce": "1777777777777aaaaaaaaabbbbbbbbbb",
        "at_hash": "222222-G-JJJJJJJJJJJJJ",
        "email": "user@example.com",
        "email_verified": true,
        "name": "Example User"
    }""")
]

function print_header(msg)
    println("")
    println("-"^60)
    println(msg)
    println("-"^60)
end

function test_and_get_keyset(url)
    print_header("keyset: $url")

    keyset = JWKSet(url)
    @test length(keyset.keys) == 0

    refresh!(keyset)
    @test length(keyset.keys) > 0
    for (k,v) in keyset.keys
        println("    ", k, " => ", v.key)
    end

    keyset
end

function test_in_mem_keyset(template)
    print_header("keyset: $template")
    keyset = JWKSet(JSON.parse(read(template, String))["keys"])
    @test length(keyset.keys) == 4
    for (k,v) in keyset.keys
        println("    ", k, " => ", v.key)
    end
end

function test_signing_keys(keyset, signingkeyset)
    for k in keys(keyset.keys)
        for d in test_payload_data
            jwt = JWT(; payload=d)
            @test claims(jwt) == d
            @test_throws AssertionError JWTs.alg(jwt)
            @test_throws AssertionError kid(jwt)
            @test !issigned(jwt)
            sign!(jwt, signingkeyset, k)
            @test issigned(jwt)
            @test isvalid(jwt)
            @test isverified(jwt)
            @test claims(jwt) == d
            @test JWTs.alg(jwt) == JWTs.alg(keyset.keys[k])
            @test kid(jwt) == k
            header = JWTs.decodepart(jwt.header)
            @test header == Dict("alg" => JWTs.alg(keyset.keys[k]), "kid" => k, "typ" => "JWT")

            println("    JWT: ", jwt)
            jwt2 = JWT(; jwt=string(jwt))
            @test claims(jwt2) == claims(jwt)
            @test JWTs.alg(jwt2) == JWTs.alg(jwt)
            @test kid(jwt2) == kid(jwt)
            @test JWTs.decodepart(jwt2.header) == JWTs.decodepart(jwt.header)
            @test issigned(jwt2)
            @test !isverified(jwt2)
            @test isvalid(jwt2) === nothing
            @test validate!(jwt, keyset, k)
            @test issigned(jwt)
            @test isvalid(jwt)
            @test isverified(jwt)

            jwt2 = JWT(; jwt=string(jwt))
            @test claims(jwt2) == claims(jwt)
            @test JWTs.alg(jwt2) == JWTs.alg(jwt)
            @test kid(jwt2) == kid(jwt)
            @test JWTs.decodepart(jwt2.header) == JWTs.decodepart(jwt.header)
            @test issigned(jwt2)
            @test !isverified(jwt2)
            @test isvalid(jwt2) === nothing
            invalidkey = findfirst(x -> x != keyset.keys[k], keyset.keys)
            @test !validate!(jwt2, keyset, invalidkey)
            @test issigned(jwt2)
            @test !isvalid(jwt2)
            @test isverified(jwt2)
        end
    end
end

function test_signing_asymmetric_keys(keyset_url)
    print_header("signing asymmetric keys")
    keyset = JWKSet(keyset_url)
    refresh!(keyset)
    signingkeyset = deepcopy(keyset)
    for k in keys(signingkeyset.keys)
        keyfile = joinpath(dirname(keyset_url), "$k.private.pem")
        if startswith(keyfile, "file://")
            keyfile = keyfile[8:end]
        end
        signingkeyset.keys[k] = JWKRSA(signingkeyset.keys[k].kind, MbedTLS.parse_keyfile(keyfile))
    end
    test_signing_keys(keyset, signingkeyset)
end

function test_signing_symmetric_keys(keyset_url)
    print_header("signing symmetric keys")
    keyset = test_and_get_keyset(keyset_url)
    test_signing_keys(keyset, keyset)
end

function test_with_valid_jwt(keyset_url)
    print_header("with_valid_jwt do block")

    keyset = JWKSet(keyset_url)
    refresh!(keyset)

    d = test_payload_data[1]
    jwt = JWT(; payload=d)
    key = first(keys(keyset.keys))
    sign!(jwt, keyset, key)

    with_valid_jwt(jwt, keyset) do jwt3
        @test isvalid(jwt3)
        @test claims(jwt3) == d
    end
    
    jwt2 = JWT(; jwt=string(jwt))
    with_valid_jwt(jwt2, keyset) do jwt3
        @test isvalid(jwt3)
        @test claims(jwt3) == d
    end
    with_valid_jwt(jwt2, keyset; kid=key) do jwt3
        @test isvalid(jwt3)
        @test claims(jwt3) == d
    end
end

test_and_get_keyset("https://www.googleapis.com/oauth2/v3/certs")
test_signing_symmetric_keys("file://" * joinpath(@__DIR__, "keys", "oct", "jwkkey.json"))
test_in_mem_keyset(joinpath(@__DIR__, "keys", "oct", "jwkkey.json"))
test_signing_asymmetric_keys("file://" * joinpath(@__DIR__, "keys", "rsa", "jwkkey.json"))
test_with_valid_jwt("file://" * joinpath(@__DIR__, "keys", "oct", "jwkkey.json"))