<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Signers;

use Mitoop\SignatureSdk\Contracts\SignerInterface;

abstract class AbstractSigner implements SignerInterface
{
    protected function requestStringToSign(string $method, string $url, string $body, int $timestamp, string $nonce): string
    {
        $path = parse_url($url, PHP_URL_PATH) ?: '';
        $query = parse_url($url, PHP_URL_QUERY);

        $uri = $path.($query === null || $query === '' ? '' : '?'.$query);

        return strtoupper($method)."\n".
            $uri."\n".
            $timestamp."\n".
            $nonce."\n".
            $body."\n";
    }

    protected function callbackStringToSign(string $timestamp, string $nonce, string $body): string
    {
        return $timestamp."\n".
            $nonce."\n".
            $body."\n";
    }
}
