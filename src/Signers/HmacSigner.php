<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Signers;

class HmacSigner extends AbstractSigner
{
    protected string $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    public function sign(string $method, string $url, string $body, int $timestamp, string $nonce): string
    {
        return $this->digest($this->requestStringToSign($method, $url, $body, $timestamp, $nonce));
    }

    public function verify(string $timestamp, string $nonce, string $body, string $signature): bool
    {
        $expected = $this->digest($this->callbackStringToSign($timestamp, $nonce, $body));

        if (strlen($expected) !== strlen($signature)) {
            return false;
        }

        return hash_equals($expected, $signature);
    }

    public function scheme(string $prefix): string
    {
        return strtoupper($prefix).'-'.SignType::SHA256_HMAC;
    }

    protected function digest(string $stringToSign): string
    {
        return base64_encode(hash_hmac('sha256', $stringToSign, trim($this->key), true));
    }
}
