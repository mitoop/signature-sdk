<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Tests;

use Mitoop\SignatureSdk\Exceptions\SignException;
use Mitoop\SignatureSdk\RequestSigner;
use Mitoop\SignatureSdk\Signers\RsaSigner;
use PHPUnit\Framework\TestCase;

final class RequestSignerTest extends TestCase
{
    public function test_authorization_uses_the_merchant_private_key(): void
    {
        [$privateKey, $publicKey] = Keys::rsa();
        $signer = new RequestSigner('10001', 'app_001', new RsaSigner($privateKey, $publicKey), 'your_app');
        $body = '{"order_id":"123456","amount":100}';
        $authorization = $signer->authorization('POST', 'https://api.example.com/api/payments', $body);

        $this->assertStringStartsWith('YOUR_APP-SHA256-RSA2048 ', $authorization);
        $this->assertMatchesRegularExpression('/mchid="10001",appid="app_001",nonce="[a-f0-9]{32}",timestamp="\d+",sign="[^"]+"/', $authorization);

        preg_match('/nonce="([^"]+)",timestamp="(\d+)",sign="([^"]+)"/', $authorization, $matches);
        $verified = openssl_verify(
            "POST\n/api/payments\n{$matches[2]}\n{$matches[1]}\n{$body}\n",
            base64_decode($matches[3]),
            $publicKey,
            OPENSSL_ALGO_SHA256
        );

        $this->assertSame(1, $verified);
    }

    public function test_prefix_must_not_contain_a_hyphen(): void
    {
        [$privateKey, $publicKey] = Keys::rsa();

        $this->expectException(SignException::class);

        new RequestSigner('10001', 'app_001', new RsaSigner($privateKey, $publicKey), 'your-app');
    }
}
