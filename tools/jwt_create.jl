using JSON
using JWTs

function main()
    largs = length(ARGS)

    if (largs < 2) || (largs > 3)
        println("Usage: julia jwt_create.jl <claims file> <keys> [key id]")
        println("    claims file: text file with JSON claim to be encoded")
        println("    keys: URL/file listing keys in standard OIDC key listing format")
        println("    key id: key id to use from the keys listed (optional, first key in list if not specified)")
        exit(1)
    end

    keysurl = ARGS[2]
    if !(startswith(keysurl, "http://") || startswith(keysurl, "https://") || startswith(keysurl, "file://")) && isfile(keysurl)
        keysurl = "file://" * keysurl
    end
    @info("using keys from " * keysurl)
    keyset = JWKSet(keysurl)
    refresh!(keyset)
    kid = (largs == 3) ? ARGS[3] : first(keys(keyset.keys))
    @info("using key id " * kid)

    jwt = JWT(; payload=JSON.parse(readchomp(ARGS[1])))
    sign!(jwt, keyset, kid)
    println(string(jwt))
end

main()
