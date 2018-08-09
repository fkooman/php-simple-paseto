# Introduction

This is a very simple 
[PASETO](https://paseto.io/rfc/) implementation written for PHP >= 5.4. It 
**ONLY** supports `v2.public` and nothing else.

**NOTE** only 64 bit PHP installations are supported!

**NOTE** if you are looking for a proper supported implementation of PASETO, 
please use [paragonie/paseto](https://github.com/paragonie/paseto).

# What?

A tiny library that just implements `Version2::sign` and `Version2::verify` of 
the [paragonie/paseto](https://github.com/paragonie/paseto) project. In 
addition it has a `Version2::extractFooter` method for extracting the footer 
to select the correct public key for verifying the signature.

It uses the official test vectors to make sure everything works as expected.

# Why?

I really like the idea of PASETO! I need to support PHP >= 5.4, so I can't use
[paragonie/paseto](https://github.com/paragonie/paseto) as it requires 
PHP >= 7. So I decided to make a tiny implementation that just supports 
`v2.public` for my 
[OAuth Server](https://git.tuxed.net/fkooman/php-oauth2-server).

# How 

The API of `Version2` is the same as in 
[paragonie/paseto](https://github.com/paragonie/paseto).

## Example 

    <?php
    require_once 'vendor/autoload.php';

    $keyPair = sodium_crypto_sign_keypair();
    $secretKey = sodium_crypto_sign_secretkey($keyPair);
    $publicKey = sodium_crypto_sign_publickey($keyPair);

    $signMsg = \fkooman\Paseto\Version2::sign('hello', $secretKey);
    // 'hello'
    echo \fkooman\Paseto\Version2::verify($signMsg, $publicKey) . PHP_EOL;

# Contact

You can contact me with any questions or issues regarding this project. Drop
me a line at [fkooman@tuxed.net](mailto:fkooman@tuxed.net).

If you want to (responsibly) disclose a security issue you can also use the
PGP key with key ID `9C5EDD645A571EB2` and fingerprint
`6237 BAF1 418A 907D AA98  EAA7 9C5E DD64 5A57 1EB2`.

# License 

ISC, same as [paragonie/paseto](https://github.com/paragonie/paseto). I 
copy/pasted some code snippets/docblocks from this library and used them here.
