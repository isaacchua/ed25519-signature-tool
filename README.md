# Ed25519 Signature Tool Documentation

[This tool](https://isaacchua.github.io/ed25519-signature-tool/Ed25519.html) is used to generate keys, sign, and verify using the Ed25519 signature algorithm in the context of:

* JSON Web Signature (JWS) [[RFC7515](https://datatracker.ietf.org/doc/html/rfc7515)]
* JSON Web Key (JWK) [[RFC7517](https://datatracker.ietf.org/doc/html/rfc7517)]
* JSON Web Key (JWK) Thumbprint [[RFC7638](https://datatracker.ietf.org/doc/html/rfc7638)]
* Edwards-Curve Digital Signature Algorithm (EdDSA) [[RFC8032](https://datatracker.ietf.org/doc/html/rfc8032)]
* CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE) [[RFC8037](https://datatracker.ietf.org/doc/html/rfc8037)]


The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

All Base64 data used in this tool conform to the Base 64 URL-safe encoding without padding characters defined in [RFC 4648 section 5](https://datatracker.ietf.org/doc/html/rfc4648#section-5).

Built using [libsodium.js](https://github.com/jedisct1/libsodium.js), the JavaScript port of [libsodium](https://libsodium.gitbook.io/), [jQuery](https://jquery.com/), and [HTML5 Boilerplate](https://html5boilerplate.com/).

License: [MIT](LICENSE)
