<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Contracts;

interface RequestSignerInterface
{
    public function authorization(string $method, string $url, string $body): string;

    public function verify(string $timestamp, string $nonce, string $body, string $signature): bool;
}
