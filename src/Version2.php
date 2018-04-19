<?php

namespace fkooman\Paseto;

use fkooman\Paseto\Exception\PasetoException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;

class Version2
{
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
        // XXX validate secret key
        $header = 'v2.public.';
        $signature = \sodium_crypto_sign_detached(
            self::preAuthEncode([$header, $data, $footer]),
            $key
        );

        $message = $header.rtrim(Base64UrlSafe::encode($data.$signature), '=');
        if ('' === $footer) {
            return $message;
        }

        return $message.'.'.rtrim(Base64UrlSafe::encode($footer), '=');
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
        // XXX validate public key
        $signMsg = self::validateAndRemoveFooter($signMsg, $footer);

        $expectHeader = 'v2.public.';
        $givenHeader = Binary::safeSubstr($signMsg, 0, 10);
        if (!\hash_equals($expectHeader, $givenHeader)) {
            throw new PasetoException('Invalid message header.');
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, 10));
        $len = Binary::safeStrlen($decoded);
        // Separate the decoded bundle into the message and signature.
        $message = Binary::safeSubstr(
            $decoded,
            0,
            $len - SODIUM_CRYPTO_SIGN_BYTES
        );
        $signature = Binary::safeSubstr(
            $decoded,
            $len - SODIUM_CRYPTO_SIGN_BYTES
        );
        $valid = \sodium_crypto_sign_verify_detached(
            $signature,
            self::preAuthEncode([$givenHeader, $message, $footer]),
            $key
        );
        if (!$valid) {
            throw new PasetoException('invalid sig');
        }

        return $message;
    }

    /**
     * Parse a string into a deconstructed PasetoMessage object.
     *
     * @param string $tainted tainted user-provided string
     *
     * @return string
     */
    public static function getFooter($tainted)
    {
        // XXX make sure it starts with "v2.public."
        /** @var array<int, string> $pieces */
        $pieces = \explode('.', $tainted);
        $count = \count($pieces);
        if ($count < 3 || $count > 4) {
            throw new PasetoException('Truncated or invalid token');
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
        $footer = rtrim(Base64UrlSafe::encode($footer), '=');
        $payload_len = Binary::safeStrlen($payload);
        $footer_len = Binary::safeStrlen($footer) + 1;
        $trailing = Binary::safeSubstr(
            $payload,
            $payload_len - $footer_len,
            $footer_len
        );
        if (!\hash_equals('.'.$footer, $trailing)) {
            throw new PasetoException('Invalid message footer');
        }

        return Binary::safeSubstr($payload, 0, $payload_len - $footer_len);
    }
}
