<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Signers;

use Mitoop\SignatureSdk\Pem;

trait KeyFormatTrait
{
    protected string $privateKey;

    protected string $publicKey;

    public function __construct(string $privateKey, string $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    protected function formatPrivateKey(string $key): string
    {
        return Pem::format($key, 'private');
    }

    protected function formatPublicKey(string $key): string
    {
        return Pem::format($key, 'public');
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
