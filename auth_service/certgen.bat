openssl genrsa -out private.pem 3072
openssl rsa -in private.pem -pubout -out public.pem