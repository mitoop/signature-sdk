<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Tests;

use Mitoop\SignatureSdk\Signers\Ed25519Signer;
use Mitoop\SignatureSdk\Signers\HmacSigner;
use Mitoop\SignatureSdk\Signers\RsaSigner;
use PHPUnit\Framework\TestCase;

final class SignerTest extends TestCase
{
    public function test_rsa_signs_the_request_and_verifies_the_callback(): void
    {
        [$privateKey, $publicKey] = Keys::rsa();
        $signer = new RsaSigner($privateKey, $publicKey);
        $body = '{"order_id":"123456","amount":100}';
        $signature = $signer->sign('POST', 'https://api.example.com/api/payments', $body, 1710000000, 'abc');

        $verified = openssl_verify(
            "POST\n/api/payments\n1710000000\nabc\n{$body}\n",
            base64_decode($signature),
            $publicKey,
            OPENSSL_ALGO_SHA256
        );

        $this->assertSame(1, $verified);
        openssl_sign("1710000000\nabc\n{$body}\n", $callback, $privateKey, OPENSSL_ALGO_SHA256);
        $this->assertTrue($signer->verify('1710000000', 'abc', $body, base64_encode($callback)));
        $this->assertFalse($signer->verify('1710000000', 'abc', $body, '@@@'));
    }

    public function test_hmac_signs_the_request_and_rejects_a_short_signature(): void
    {
        $signer = new HmacSigner('secret');
        $body = '{"order_id":"123456","amount":100}';
        $signature = $signer->sign('POST', 'https://api.example.com/api/payments?x=1', $body, 1710000000, 'abc');
        $expected = base64_encode(hash_hmac(
            'sha256',
            "POST\n/api/payments?x=1\n1710000000\nabc\n{$body}\n",
            'secret',
            true
        ));

        $this->assertSame($expected, $signature);
        $this->assertTrue($signer->verify('1710000000', 'abc', $body, $this->callbackHmac($body)));
        $this->assertFalse($signer->verify('1710000000', 'abc', $body, 'short'));
    }

    public function test_ed25519_signs_the_request_and_verifies_the_callback(): void
    {
        [$privateKey, $publicKey] = Keys::ed25519();
        $signer = new Ed25519Signer($privateKey, $publicKey);
        $body = '{"order_id":"123456","amount":100}';
        $signature = $signer->sign('POST', 'https://api.example.com/api/payments', $body, 1710000000, 'abc');
        $public = \phpseclib3\Crypt\EC::loadPublicKey($publicKey);

        $this->assertTrue($public->verify("POST\n/api/payments\n1710000000\nabc\n{$body}\n", base64_decode($signature)));

        $private = \phpseclib3\Crypt\EC::loadPrivateKey($privateKey);
        $callback = base64_encode($private->sign("1710000000\nabc\n{$body}\n"));

        $this->assertTrue($signer->verify('1710000000', 'abc', $body, $callback));
        $this->assertFalse($signer->verify('1710000000', 'abc', $body, '@@@'));
    }

    private function callbackHmac(string $body): string
    {
        return base64_encode(hash_hmac('sha256', "1710000000\nabc\n{$body}\n", 'secret', true));
    }
}
