# Introduction

This is a very simple 
[PASETO](https://tools.ietf.org/html/draft-paragon-paseto-rfc-00) 
implementation written for PHP >= 5.4. It **ONLY** supports `v2.public` and 
nothing else.

**NOTE** if you are looking for a proper supported implementation of PASETO, 
please use [paragonie/paseto](https://github.com/paragonie/paseto).

# What?

A tiny library that just implements `Version2::sign` and `Version2::verify` of 
the [paragonie/paseto](https://github.com/paragonie/paseto) project. In 
addition it has a `Version2::getFooter` method for extracting the footer 
to select the correct public key for verifying the signature.

It uses the official test vectors to make sure everything works as expected.

# Why?

I really like the idea of PASETO! I need to support PHP >= 5.4, so I can't use
[paragonie/paseto](https://github.com/paragonie/paseto) as it requires 
PHP >= 7. So I decided to make a tiny implementation that just supports 
`v2.public` for my 
[OAuth Server](https://github.com/fkooman/php-oauth2-server).

# License 

ISC, same as [paragonie/paseto](https://github.com/paragonie/paseto). I 
copy/pasted some code snippets/docblocks from this library and used them here.
