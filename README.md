# Auth Server
This is the implementation of an OAuth2/OpenID Connect authentication server.

## Generate JWKS file
See [Generate RSA Key Pairs with OpenSSL for signing JWT](https://www.cerberauth.com/blog/rsa-key-pairs-openssl-jwt-signature/).

### Generate a Private Key

```shell
openssl genrsa -out keys/private_key.pem 2048
```

* -out private_key.pem: Specifies the output file path for the private key.
* 2048 (bits): The private key length. It is recommended that you use a minimum
  of 2048 when using RSA 256. If you can, prefer using longer key length. The
  longer the key is, the more robust the encryption is.

### Generate a Public Key from the Private Key

```shell
openssl rsa -pubout -in keys/private_key.pem -out keys/public_key.pem
```

* -pubout: Instructs OpenSSL to generate the public key.
* -in private_key.pem: Specifies the input private key file.
* -out public_key.pem: Specifies the output file for the public key.

### View Key Details (Optional)
You can view the details of the generated private and public keys using the
following OpenSSL commands:

```shell
openssl rsa -text -in keys/private_key.pem
```

```shell
openssl rsa -pubin -text -in keys/public_key.pem
```
These commands display detailed information about the keys, including modulus,
public exponent, and more.

Remember to keep your private key secure and do not share it publicly. The
public key can be freely shared and used for verifying signatures.