openssl genrsa -out ${1}.private.pem 2048
openssl rsa -in ${1}.private.pem -outform PEM -pubout -out ${1}.public.pem
openssl rsa -pubin -in ${1}.public.pem -modulus -noout
openssl rsa -pubin -in ${1}.public.pem -text -noout
