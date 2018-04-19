<?php

namespace fkooman\Paseto\Tests;

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
        $keypair = sodium_crypto_sign_keypair();
        $privateKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year.'-01-01T00:00:00']),
        ];

        foreach ($messages as $message) {
            $signed = Version2::sign($message, $privateKey);
            $this->assertInternalType('string', $signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version2::verify($signed, $publicKey);
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version2::sign($message, $privateKey, 'footer');
            $this->assertInternalType('string', $signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version2::verify($signed, $publicKey);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version2::verify($signed, $publicKey, 'footer');
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);
        }
    }
}
