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

        $message = self::PASETO_HEADER.self::base64EncodeUnpadded($data.$signature);
        if ('' === $footer) {
            return $message;
        }

        return $message.'.'.self::base64EncodeUnpadded($footer);
    }

    /**
     * @param string      $signMsg
     * @param string      $key
     * @param null|string $footer
     *
     * @return string
     */
    public static function verify($signMsg, $key, $footer = null)
    {
        if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== Binary::safeStrlen($key)) {
            throw new PasetoException('Invalid public key length.');
        }

        self::verifyHeader($signMsg);

        if (null === $footer) {
            // we do not care about the contents of footer at all, even if it
            // is there...
            $footer = self::getFooter($signMsg);
        } else {
            // we do care about the contents of footer, and it MUST be the
            // same as we request here
            $signMsg = self::validateAndRemoveFooter($signMsg, $footer);
        }
        $signMsg = self::removeFooter($signMsg);
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
     * @param string $payload
     *
     * @return string
     */
    public static function extractFooter($payload)
    {
        self::verifyHeader($payload);

        return self::getFooter($payload);
    }

    /**
     * @param string $payload
     *
     * @return string
     */
    public static function removeFooter($payload)
    {
        $pieces = \explode('.', $payload);
        if (\count($pieces) > 3) {
            return \implode('.', \array_slice($pieces, 0, 3));
        }

        return $payload;
    }

    /**
     * @param string $payload
     *
     * @return string
     */
    private static function getFooter($payload)
    {
        /** @var array<int, string> $pieces */
        $pieces = \explode('.', $payload);
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
        $accumulator = self::LE64((int) (\count($pieces) & PHP_INT_MAX));
        foreach ($pieces as $piece) {
            $len = Binary::safeStrlen($piece);
            $accumulator .= self::LE64((int) ($len & PHP_INT_MAX));
            $accumulator .= $piece;
        }

        return $accumulator;
    }

    /**
     * @param int $n
     *
     * @return string
     */
    private static function LE64($n)
    {
        if (PHP_VERSION_ID >= 50603) {
            return \pack('P', $n);
        }

        // compat mode, for PHP < 5.6.3, taken from PASETO RFC pseudocode
        // pack('P') above is ~7 times faster than this implementation below
        // (tested on PHP 7.1.16)
        $str = '';
        for ($i = 0; $i < 8; ++$i) {
            if (7 === $i) {
                $n &= 127;
            }
            $str .= \pack('C', $n & 255);
            $n = (int) ($n >> 8);
        }

        return $str;
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
        if ('' === $footer) {
            return $payload;
        }
        $footer = self::base64EncodeUnpadded($footer);
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
    private static function base64EncodeUnpadded($str)
    {
        return \rtrim(Base64UrlSafe::encode($str), '=');
    }
}
