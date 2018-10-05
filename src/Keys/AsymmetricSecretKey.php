<?php

/*
 * Copyright (c) 2018, François Kooman <fkooman@tuxed.net>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

namespace fkooman\Paseto\Keys;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use TypeError;

class AsymmetricSecretKey
{
    /** @var string */
    private $secretKey;

    /**
     * @param string $secretKey
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function __construct($secretKey)
    {
        if (!\is_string($secretKey)) {
            throw new TypeError('argument 1 must be string');
        }
        if (SODIUM_CRYPTO_SIGN_SECRETKEYBYTES !== Binary::safeStrlen($secretKey)) {
            throw new \LengthException('invalid secret key length');
        }
        $this->secretKey = $secretKey;
    }

    /**
     * @return self
     */
    public static function generate()
    {
        return new self(
            \sodium_crypto_sign_secretkey(
                \sodium_crypto_sign_keypair()
            )
        );
    }

    /**
     * @return string
     */
    public function encode()
    {
        return Base64UrlSafe::encodeUnpadded($this->secretKey);
    }

    /**
     * @param string $encodedString
     *
     * @return self
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public static function fromEncodedString($encodedString)
    {
        if (!\is_string($encodedString)) {
            throw new TypeError('argument 1 must be string');
        }

        return new self(Base64UrlSafe::decode($encodedString));
    }

    /**
     * @return AsymmetricPublicKey
     */
    public function getPublicKey()
    {
        return new AsymmetricPublicKey(
            \sodium_crypto_sign_publickey_from_secretkey($this->secretKey)
        );
    }

    /**
     * @return string
     */
    public function raw()
    {
        return $this->secretKey;
    }
}
