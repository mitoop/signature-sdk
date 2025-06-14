<?php

namespace Mitoop\SignatureSdk;

class HmacSigner extends AbstractSigner
{
    protected string $secretKey;

    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    public function sign(array $args): string
    {
        return base64_encode(hash_hmac('sha256', $this->buildRequestMessage($args), $this->getSecretKey(), true));
    }

    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool
    {
        return hash_equals(
            base64_encode(hash_hmac('sha256', $this->buildCallbackMessage($timestamp, $nonce, $data), $this->getSecretKey(), true)),
            $signature
        );
    }

    public function getAlgorithmHeader(string $prefix): string
    {
        return sprintf('%s-%s', $prefix, 'SHA256-HMAC');
    }

    protected function getSecretKey(): string
    {
        return trim($this->secretKey);
    }
}
