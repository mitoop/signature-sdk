<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Signers;

use Mitoop\SignatureSdk\Exceptions\SignException;

class RsaSigner extends AbstractSigner
{
    use KeyFormatTrait;

    /**
     * @throws SignException
     */
    public function sign(string $method, string $url, string $body, int $timestamp, string $nonce): string
    {
        $signed = openssl_sign(
            $this->requestStringToSign($method, $url, $body, $timestamp, $nonce),
            $signature,
            $this->formatPrivateKey($this->getPrivateKey()),
            OPENSSL_ALGO_SHA256
        );

        if (! $signed) {
            throw new SignException('Sign failed: '.(openssl_error_string() ?: 'unknown error'));
        }

        return base64_encode($signature);
    }

    public function verify(string $timestamp, string $nonce, string $body, string $signature): bool
    {
        $decoded = base64_decode($signature, true);

        if ($decoded === false) {
            return false;
        }

        return openssl_verify(
            $this->callbackStringToSign($timestamp, $nonce, $body),
            $decoded,
            $this->formatPublicKey($this->getPublicKey()),
            OPENSSL_ALGO_SHA256
        ) === 1;
    }

    public function scheme(string $prefix): string
    {
        return strtoupper($prefix).'-'.SignType::SHA256_RSA2048;
    }
}
