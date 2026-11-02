<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Mitoop\SignatureSdk\Client;
use Mitoop\SignatureSdk\RequestSigner;
use Mitoop\SignatureSdk\Signers\RsaSigner;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    public function test_post_signs_the_json_body_that_is_sent(): void
    {
        [$privateKey, $publicKey] = Keys::rsa();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'success')]));
        $stack->push(Middleware::history($history));
        $client = new Client(
            ['base_url' => 'https://api.example.com'],
            new RequestSigner('10001', 'app_001', new RsaSigner($privateKey, $publicKey), 'your_app'),
            new GuzzleClient(['handler' => $stack, 'http_errors' => false])
        );

        $response = $client->post('/api/payments', ['order_id' => '123456', 'amount' => 100]);
        $request = $history[0]['request'];
        $body = (string) $request->getBody();
        $authorization = $request->getHeaderLine('Authorization');

        preg_match('/nonce="([^"]+)",timestamp="(\d+)",sign="([^"]+)"/', $authorization, $matches);
        $verified = openssl_verify(
            "POST\n/api/payments\n{$matches[2]}\n{$matches[1]}\n{$body}\n",
            base64_decode($matches[3]),
            $publicKey,
            OPENSSL_ALGO_SHA256
        );

        $this->assertSame('{"order_id":"123456","amount":100}', $body);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(1, $verified);
    }
}
