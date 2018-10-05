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
use fkooman\Paseto\Keys\AsymmetricPublicKey;
use fkooman\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use RuntimeException;
use TypeError;

class Version2
{
    const PASETO_HEADER = 'v2.public.';

    /**
     * @param string              $msgData
     * @param AsymmetricSecretKey $secretKey
     * @param string              $msgFooter
     *
     * @throws \LengthException
     *
     * @return string
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public static function sign($msgData, AsymmetricSecretKey $secretKey, $msgFooter = '')
    {
        if (!\is_string($msgData)) {
            throw new TypeError('argument 1 must be string');
        }
        if (!\is_string($msgFooter)) {
            throw new TypeError('argument 3 must be string');
        }

        $msgSig = \sodium_crypto_sign_detached(
            self::preAuthEncode(
                [
                    self::PASETO_HEADER,
                    $msgData,
                    $msgFooter,
                ]
            ),
            $secretKey->raw()
        );

        $signMsg = self::PASETO_HEADER.Base64UrlSafe::encodeUnpadded($msgData.$msgSig);
        if ('' === $msgFooter) {
            return $signMsg;
        }

        return $signMsg.'.'.Base64UrlSafe::encodeUnpadded($msgFooter);
    }

    /**
     * @param string              $signMsg
     * @param AsymmetricPublicKey $publicKey
     * @param null|string         $expectedFooter
     *
     * @throws PasetoException
     * @throws \RangeException
     * @throws \LengthException
     *
     * @return string
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public static function verify($signMsg, AsymmetricPublicKey $publicKey, $expectedFooter = null)
    {
        if (!\is_string($signMsg)) {
            throw new TypeError('argument 1 must be string');
        }
        if (null !== $expectedFooter && !\is_string($expectedFooter)) {
            throw new TypeError('argument 3 must be null|string');
        }

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
            $publicKey->raw()
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
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public static function extractFooter($signMsg)
    {
        if (!\is_string($signMsg)) {
            throw new TypeError('argument 1 must be string');
        }

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
        $accumulator = self::intToByteArray((int) (\count($pieces) & PHP_INT_MAX));
        foreach ($pieces as $piece) {
            $len = Binary::safeStrlen($piece);
            $accumulator .= self::intToByteArray((int) ($len & PHP_INT_MAX));
            $accumulator .= $piece;
        }

        return $accumulator;
    }

    /**
     * @see paragonie/sodium_compat
     *
     * @param int $int
     *
     * @return string
     */
    private static function intToByteArray($int)
    {
        if (8 !== PHP_INT_SIZE) {
            throw new RuntimeException('only 64 bit PHP installations are supported');
        }

        if (\PHP_VERSION_ID >= 50603) {
            return \pack('P', $int);
        }

        return \pack('C', $int & 0xff).
            \pack('C', ($int >> 8) & 0xff).
            \pack('C', ($int >> 16) & 0xff).
            \pack('C', ($int >> 24) & 0xff).
            \pack('C', ($int >> 32) & 0xff).
            \pack('C', ($int >> 40) & 0xff).
            \pack('C', ($int >> 48) & 0xff).
            \pack('C', ($int >> 56) & 0xff);
    }
}
