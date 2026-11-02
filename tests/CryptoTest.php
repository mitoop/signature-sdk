<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Tests;

use Mitoop\SignatureSdk\Crypto\AesGcm;
use Mitoop\SignatureSdk\Crypto\Rsa;
use Mitoop\SignatureSdk\Crypto\RsaAesGcm;
use Mitoop\SignatureSdk\Exceptions\CryptoException;
use PHPUnit\Framework\TestCase;

final class CryptoTest extends TestCase
{
    public function test_aes_gcm_decrypts_the_base64_iv_returned_by_encrypt(): void
    {
        $aes = new AesGcm;
        $key = random_bytes(32);
        $encrypted = $aes->encrypt('hello', $key, 'aad');

        $this->assertSame('hello', $aes->decrypt(
            $encrypted['ciphertext'],
            $key,
            $encrypted['iv'],
            $encrypted['associated_data']
        ));
    }

    public function test_aes_gcm_rejects_a_raw_iv(): void
    {
        $aes = new AesGcm;
        $encrypted = $aes->encrypt('hello', random_bytes(32));

        $this->expectException(CryptoException::class);

        $aes->decrypt($encrypted['ciphertext'], random_bytes(32), random_bytes(12));
    }

    public function test_rsa_round_trip(): void
    {
        [$privateKey, $publicKey] = Keys::rsa();
        $rsa = new Rsa;

        $this->assertSame('hello', $rsa->decrypt($rsa->encrypt('hello', $publicKey), $privateKey));
    }

    public function test_rsa_aes_gcm_round_trip(): void
    {
        [$privateKey, $publicKey] = Keys::rsa();
        $cipher = new RsaAesGcm;
        $encrypted = $cipher->encrypt('hello', $publicKey, 'aad');

        $this->assertSame('hello', $cipher->decrypt(
            $encrypted['encrypted_key'],
            $encrypted['ciphertext'],
            $privateKey,
            $encrypted['iv'],
            $encrypted['associated_data']
        ));
    }
}
