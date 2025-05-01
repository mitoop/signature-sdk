<?php

namespace Mitoop\SignatureSdk;

use InvalidArgumentException;

class RsaSigner extends AbstractSigner
{
    protected string $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * @throws SignException
     */
    public function sign(array $args): string
    {
        if (! openssl_sign($this->buildRequestMessage($args), $signature, $this->formatPrivateKey($this->key), OPENSSL_ALGO_SHA256)) {
            throw new SignException('签名失败：'.(openssl_error_string() ?: '未知错误'));
        }

        return base64_encode($signature);
    }

    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool
    {
        return openssl_verify(
            $this->buildCallbackMessage($timestamp, $nonce, $data),
            base64_decode($signature),
            $this->formatPublicKey($this->key),
            OPENSSL_ALGO_SHA256) === 1;
    }

    protected function formatKey(string $key, string $type): string
    {
        $headers = [
            'private' => ['BEGIN PRIVATE KEY', 'END PRIVATE KEY'],
            'public' => ['BEGIN PUBLIC KEY', 'END PUBLIC KEY'],
        ];

        if (! isset($headers[$type])) {
            throw new InvalidArgumentException("Unsupported key type: $type");
        }

        [$begin, $end] = $headers[$type];

        return "-----$begin-----\n".
            wordwrap($key, 64, "\n", true).
            "\n-----$end-----";
    }

    protected function formatPrivateKey(string $key): string
    {
        return $this->formatKey($key, 'private');
    }

    protected function formatPublicKey(string $key): string
    {
        return $this->formatKey($key, 'public');
    }
}
