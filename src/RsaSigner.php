<?php

namespace Mitoop\SignatureSdk;

class RsaSigner extends AbstractSigner
{
    protected string $privateKey;

    public function __construct(string $privateKey)
    {
        $this->privateKey = $this->formatPrivateKey($privateKey);
    }

    /**
     * @throws SignException
     */
    public function sign(array $args): string
    {
        if (! openssl_sign($this->buildMessage($args), $signature, $this->privateKey, OPENSSL_ALGO_SHA256)) {
            throw new SignException('签名失败：'.(openssl_error_string() ?: '未知错误'));
        }

        return base64_encode($signature);
    }

    protected function formatPrivateKey(string $key): string
    {
        return "-----BEGIN PRIVATE KEY-----\n".
            wordwrap($key, 64, "\n", true).
            "\n-----END PRIVATE KEY-----";
    }
}
