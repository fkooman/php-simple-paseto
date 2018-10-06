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

namespace fkooman\Paseto\Tests;

use fkooman\Paseto\Keys\AsymmetricPublicKey;
use fkooman\Paseto\Keys\AsymmetricSecretKey;
use fkooman\Paseto\Version2;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class Version2VectorTest.
 *
 * Contains test vectors for building compatible implementations in other languages.
 */
class Version2VectorTest extends TestCase
{
    /** @var \fkooman\Paseto\AsymmetricSecretKey */
    protected $privateKey;

    /** @var \fkooman\Paseto\AsymmetricPublicKey */
    protected $publicKey;

    /**
     * This just sets up two asymmetric keys, generated once
     * upon a time, to facilitate the standard test vectors.
     *
     * DO NOT USE THESE KEYS EVER FOR ANY PURPOSE OTHER THAN
     * VERIFYING THE PROVIDED TEST VECTORS FOR VERSION 2.
     */
    public function setUp()
    {
        $this->privateKey = new AsymmetricSecretKey(Hex::decode(
            'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774'.
            '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'
        ));

        $this->publicKey = new AsymmetricPublicKey(Hex::decode(
            '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'
        ));
    }

    /**
     * @throws PasetoException
     */
    public function testOfficialVectors()
    {
        $footer = '';
        $message = \json_encode(['data' => 'this is a signed message', 'exp' => '2019-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw',
            Version2::sign($message, $this->privateKey, $footer),
            'Test Vector 2-S-1'
        );
    }

    public function testSignVectors()
    {
        // Empty string, 32-character NUL byte key.
        $this->assertSame(
            'v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA',
            Version2::sign('', $this->privateKey),
            'Test Vector S-1'
        );

        // Empty string, 32-character NUL byte key, non-empty footer.
        $this->assertSame(
            'v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz',
            Version2::sign('', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector S-2'
        );

        // Non-empty string, 32-character 0xFF byte key.
        $this->assertSame(
            'v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM',
            Version2::sign('Frank Denis rocks', $this->privateKey),
            'Test Vector S-3'
        );

        // Non-empty string, 32-character 0xFF byte key. (One character difference)
        $this->assertSame(
            'v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML',
            Version2::sign('Frank Denis rockz', $this->privateKey),
            'Test Vector S-4'
        );

        // Non-empty string, 32-character 0xFF byte key, non-empty footer.
        $this->assertSame(
            'v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz',
            Version2::sign('Frank Denis rocks', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector S-5'
        );

        $message = \json_encode(['data' => 'this is a signed message', 'expires' => '2019-01-01T00:00:00+00:00']);
        $footer = 'Paragon Initiative Enterprises';
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI',
            Version2::sign($message, $this->privateKey),
            'Test Vector S-6'
        );
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
            Version2::sign($message, $this->privateKey, $footer),
            'Test Vector S-6'
        );

        $message = \json_encode(['data' => 'this is a signed message', 'exp' => '2019-01-01T00:00:00+00:00']);
        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            Version2::sign($message, $this->privateKey, $footer),
            'Test Vector 2E-6'
        );
    }
}
