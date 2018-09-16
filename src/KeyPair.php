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

namespace fkooman\Paseto;

use ParagonIE\ConstantTime\Binary;

class KeyPair
{
    /** @var string */
    private $keyPair;

    /**
     * @param string $keyPair
     */
    public function __construct($keyPair)
    {
        if (SODIUM_CRYPTO_SIGN_KEYPAIRBYTES !== Binary::safeStrlen($keyPair)) {
            throw new \LengthException('Invalid keypair length.');
        }
        $this->keyPair = $keyPair;
    }

    /**
     * @return self
     */
    public static function generate()
    {
        return new self(\sodium_crypto_sign_keypair());
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey()
    {
        return new PublicKey(\sodium_crypto_sign_publickey($this->keyPair));
    }

    /**
     * @return SecretKey
     */
    public function getSecretKey()
    {
        return new SecretKey(\sodium_crypto_sign_secretkey($this->keyPair));
    }
}
