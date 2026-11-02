<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk;

final class Pem
{
    public static function format(string $key, string $type): string
    {
        $key = trim($key);

        if (strpos($key, '-----BEGIN ') === 0) {
            return $key;
        }

        $label = strtoupper($type);
        $body = preg_replace('/\s+/', '', $key) ?? $key;

        return "-----BEGIN {$label} KEY-----\n"
            .chunk_split($body, 64, "\n")
            ."-----END {$label} KEY-----\n";
    }
}
