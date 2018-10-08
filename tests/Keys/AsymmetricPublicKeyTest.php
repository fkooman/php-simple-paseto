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

namespace fkooman\Paseto\Tests\Keys;

use fkooman\Paseto\Keys\AsymmetricPublicKey;
use PHPUnit\Framework\TestCase;

class AsymmetricPublicKeyTest extends TestCase
{
    public function testFromEncodedString()
    {
        $publicKey = AsymmetricPublicKey::fromEncodedString(
            'n4o_PJoQ5gUCeIdlTGPee4z0-tRFdgWVJDcgmRe_qBE'
        );
        $this->assertSame(
            '9pZgMe8bC9buTlZoK7fS1Gb7tOYFnfrCuMHMQ7Nn7rE',
            $publicKey->getKeyId()
        );
        $this->assertSame(
            '9f8a3f3c9a10e605027887654c63de7b8cf4fad4457605952437209917bfa811',
            \bin2hex($publicKey->raw())
        );
        $publicKey = new AsymmetricPublicKey(\hex2bin('9f8a3f3c9a10e605027887654c63de7b8cf4fad4457605952437209917bfa811'));
        $this->assertSame(
            'n4o_PJoQ5gUCeIdlTGPee4z0-tRFdgWVJDcgmRe_qBE',
            $publicKey->encode()
        );
    }
}
