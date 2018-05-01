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
     * @param string $msgData
     * @param string $secretKey
     * @param string $msgFooter
     *
     * @throws \LengthException
     *
     * @return string
     */
    public static function sign($msgData, $secretKey, $msgFooter = '')
    {
        self::verifySecretKey($secretKey);
        $msgSig = \sodium_crypto_sign_detached(
            self::preAuthEncode(
                [
                    self::PASETO_HEADER,
                    $msgData,
                    $msgFooter,
                ]
            ),
            $secretKey
        );

        $signMsg = self::PASETO_HEADER.self::encodeUnpadded($msgData.$msgSig);
        if ('' === $msgFooter) {
            return $signMsg;
        }

        return $signMsg.'.'.self::encodeUnpadded($msgFooter);
    }

    /**
     * @param string      $signMsg
     * @param string      $publicKey
     * @param null|string $expectedFooter
     *
     * @throws PasetoException
     * @throws \RangeException
     * @throws \LengthException
     *
     * @return string
     */
    public static function verify($signMsg, $publicKey, $expectedFooter = null)
    {
        self::verifyPublicKey($publicKey);
        list($msgPayload, $msgFooter) = self::parseMessage($signMsg);
        if (null === $expectedFooter) {
            $expectedFooter = $msgFooter;
        }

        if (!\hash_equals($expectedFooter, $msgFooter)) {
            throw new PasetoException('Invalid message footer.');
        }

        $msgPayloadLen = Binary::safeStrlen($msgPayload);
        $msgData = Binary::safeSubstr($msgPayload, 0, $msgPayloadLen - SODIUM_CRYPTO_SIGN_BYTES);
        $msgSig = Binary::safeSubstr($msgPayload, $msgPayloadLen - SODIUM_CRYPTO_SIGN_BYTES);
        $valid = \sodium_crypto_sign_verify_detached(
            $msgSig,
            self::preAuthEncode([self::PASETO_HEADER, $msgData, $expectedFooter]),
            $publicKey
        );
        if (false === $valid) {
            throw new PasetoException('Invalid signature.');
        }

        return $msgData;
    }

    /**
     * @param string $signMsg
     *
     * @throws PasetoException
     * @throws \RangeException
     *
     * @return string
     */
    public static function extractFooter($signMsg)
    {
        return self::parseMessage($signMsg)[1];
    }

    /**
     * @param string $signMsg
     *
     * @throws PasetoException
     * @throws \RangeException
     *
     * @return array<int, string>
     */
    private static function parseMessage($signMsg)
    {
        if (!\hash_equals(self::PASETO_HEADER, Binary::safeSubstr($signMsg, 0, 10))) {
            throw new PasetoException('Invalid message header.');
        }
        $pieces = \explode('.', $signMsg);
        $count = \count($pieces);
        switch ($count) {
            case 3:
                return [Base64UrlSafe::decode($pieces[2]), ''];
            case 4:
                return [Base64UrlSafe::decode($pieces[2]), Base64UrlSafe::decode($pieces[3])];
            default:
                throw new PasetoException('Truncated or invalid token.');
        }
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
     * @param string $publicKey
     *
     * @throws \LengthException
     *
     * @return void
     */
    private static function verifyPublicKey($publicKey)
    {
        if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== Binary::safeStrlen($publicKey)) {
            throw new \LengthException('Invalid public key length.');
        }
    }

    /**
     * @param string $secretKey
     *
     * @throws \LengthException
     *
     * @return void
     */
    private static function verifySecretKey($secretKey)
    {
        if (SODIUM_CRYPTO_SIGN_BYTES !== Binary::safeStrlen($secretKey)) {
            throw new \LengthException('Invalid secret key length.');
        }
    }

    /**
     * @param string $str
     *
     * @return string
     */
    private static function encodeUnpadded($str)
    {
        // check if Base64UrlSafe::encodeUnpadded exists, only on
        // paragonie/constant_time_encoding >= 1.0.3, >= 2.2.0
        if (\method_exists('ParagonIE\ConstantTime\Base64UrlSafe', 'encodeUnpadded')) {
            return Base64UrlSafe::encodeUnpadded($str);
        }

        return \rtrim(Base64UrlSafe::encode($str), '=');
    }
}
