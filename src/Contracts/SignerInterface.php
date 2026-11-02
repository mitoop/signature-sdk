<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Contracts;

interface SignerInterface
{
    public function sign(string $method, string $url, string $body, int $timestamp, string $nonce): string;

    public function verify(string $timestamp, string $nonce, string $body, string $signature): bool;

    public function scheme(string $prefix): string;
}
