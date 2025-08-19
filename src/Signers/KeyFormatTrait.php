<?php

namespace Mitoop\SignatureSdk\Signers;

trait KeyFormatTrait
{
    protected string $privateKey;

    protected string $publicKey;

    public function __construct(string $privateKey, string $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    protected function formatKey(string $key, string $type): string
    {
        $type = strtoupper($type);

        $pemHeader = "-----BEGIN $type KEY-----";

        if (strpos($key, $pemHeader) !== false) {
            return $key;
        }

        return "-----BEGIN $type KEY-----\n"
            .chunk_split($key, 64, "\n")
            ."-----END $type KEY-----\n";
    }

    protected function formatPrivateKey(string $key): string
    {
        return $this->formatKey($key, 'private');
    }

    protected function formatPublicKey(string $key): string
    {
        return $this->formatKey($key, 'public');
    }

    protected function getPrivateKey(): string
    {
        return trim($this->privateKey);
    }

    protected function getPublicKey(): string
    {
        return trim($this->publicKey);
    }
}
