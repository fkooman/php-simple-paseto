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

use fkooman\Paseto\Exception\PasetoException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;

class Version2
{
    const PASETO_HEADER = 'v2.public.';

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param string $key
     * @param string $footer
     *
     * @return string
     */
    public static function sign($data, $key, $footer = '')
    {
        if (SODIUM_CRYPTO_SIGN_BYTES !== Binary::safeStrlen($key)) {
            throw new PasetoException('Invalid secret key length.');
        }

        $signature = \sodium_crypto_sign_detached(
            self::preAuthEncode([self::PASETO_HEADER, $data, $footer]),
            $key
        );

        $message = self::PASETO_HEADER.self::encode($data.$signature);
        if ('' === $footer) {
            return $message;
        }

        return $message.'.'.self::encode($footer);
    }

    /**
     * Verify a signed message. Public-key digital signatures.
     *
     * @param string $signMsg
     * @param string $key
     * @param string $footer
     *
     * @return string
     */
    public static function verify($signMsg, $key, $footer = '')
    {
        if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== Binary::safeStrlen($key)) {
            throw new PasetoException('Invalid public key length.');
        }

        $signMsg = self::validateAndRemoveFooter($signMsg, $footer);
        self::verifyHeader($signMsg);
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, 10));
        $len = Binary::safeStrlen($decoded);
        // Separate the decoded bundle into the message and signature.
        $message = Binary::safeSubstr($decoded, 0, $len - SODIUM_CRYPTO_SIGN_BYTES);
        $signature = Binary::safeSubstr($decoded, $len - SODIUM_CRYPTO_SIGN_BYTES);
        $valid = \sodium_crypto_sign_verify_detached(
            $signature,
            self::preAuthEncode([self::PASETO_HEADER, $message, $footer]),
            $key
        );
        if (false === $valid) {
            throw new PasetoException('Invalid signature.');
        }

        return $message;
    }

    /**
     * @param string $tainted tainted user-provided string
     *
     * @return string
     */
    public static function getFooter($tainted)
    {
        self::verifyHeader($tainted);
        /** @var array<int, string> $pieces */
        $pieces = \explode('.', $tainted);
        $count = \count($pieces);
        if ($count < 3 || $count > 4) {
            throw new PasetoException('Truncated or invalid token.');
        }

        return $count > 3 ? Base64UrlSafe::decode($pieces[3]) : '';
    }

    /**
     * Format the Additional Associated Data.
     *
     * Prefix with the length (64-bit unsigned little-endian integer)
     * followed by each message. This provides a more explicit domain
     * separation between each piece of the message.
     *
     * Each length is masked with PHP_INT_MAX using bitwise AND (&) to
     * clear out the MSB of the total string length.
     *
     * @param array<int, string> $pieces
     *
     * @return string
     */
    private static function preAuthEncode(array $pieces)
    {
        $accumulator = \pack('P', \count($pieces) & PHP_INT_MAX);
        foreach ($pieces as $piece) {
            $len = Binary::safeStrlen($piece);
            $accumulator .= \pack('P', $len & PHP_INT_MAX);
            $accumulator .= $piece;
        }

        return $accumulator;
    }

    /**
     * If a footer was included with the message, first verify that
     * it's equivalent to the one we expect, then remove it from the
     * token payload.
     *
     * @param string $payload
     * @param string $footer
     *
     * @return string
     */
    private static function validateAndRemoveFooter($payload, $footer = '')
    {
        if (empty($footer)) {
            return $payload;
        }
        $footer = self::encode($footer);
        $payload_len = Binary::safeStrlen($payload);
        $footer_len = Binary::safeStrlen($footer) + 1;
        $trailing = Binary::safeSubstr(
            $payload,
            $payload_len - $footer_len,
            $footer_len
        );
        if (!\hash_equals('.'.$footer, $trailing)) {
            throw new PasetoException('Invalid message footer.');
        }

        return Binary::safeSubstr($payload, 0, $payload_len - $footer_len);
    }

    /**
     * @param string $signMsg
     *
     * @return void
     */
    private static function verifyHeader($signMsg)
    {
        $givenHeader = Binary::safeSubstr($signMsg, 0, 10);
        if (!\hash_equals(self::PASETO_HEADER, $givenHeader)) {
            throw new PasetoException('Invalid message header.');
        }
    }

    /**
     * @param string $str
     *
     * @return string
     */
    private static function encode($str)
    {
        return \rtrim(Base64UrlSafe::encode($str), '=');
    }
}
