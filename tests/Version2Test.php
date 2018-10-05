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

use fkooman\Paseto\Exception\PasetoException;
use fkooman\Paseto\Keys\AsymmetricSecretKey;
use fkooman\Paseto\Version2;
use ParagonIE\ConstantTime\Binary;
use PHPUnit\Framework\TestCase;

class Version2Test extends TestCase
{
    /**
     * @covers \Version2::sign()
     * @covers \Version2::verify()
     */
    public function testSign()
    {
        $secretKey = AsymmetricSecretKey::generate();
        $publicKey = $secretKey->getPublicKey();

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year.'-01-01T00:00:00']),
        ];

        foreach ($messages as $message) {
            $signed = Version2::sign($message, $secretKey);
            $this->assertInternalType('string', $signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version2::verify($signed, $publicKey);
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version2::sign($message, $secretKey, 'footer');
            $this->assertInternalType('string', $signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version2::verify($signed, $publicKey, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
            $decode = Version2::verify($signed, $publicKey, 'footer');
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);
        }
    }

    public function testExtractFooter()
    {
        $this->assertSame(
            '',
            Version2::extractFooter(
                'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI'
            )
        );

        $this->assertSame(
            'Paragon Initiative Enterprises',
            Version2::extractFooter(
    'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz'
            )
        );
    }
}
