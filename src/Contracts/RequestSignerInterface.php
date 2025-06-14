<?php

namespace Mitoop\SignatureSdk\Contracts;

interface RequestSignerInterface
{
    public function sign(string $method, string $url, ?array $data = null): string;

    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool;
}
