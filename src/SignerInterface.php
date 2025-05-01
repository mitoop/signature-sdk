<?php

namespace Mitoop\SignatureSdk;

interface SignerInterface
{
    public function sign(array $args): string;

    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool;

    public function getAlgorithmHeader(string $prefix): string;
}
