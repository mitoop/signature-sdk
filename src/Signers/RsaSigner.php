<?php

namespace Mitoop\SignatureSdk\Signers;

use Mitoop\SignatureSdk\Exceptions\SignException;

class RsaSigner extends AbstractSigner
{
    use KeyFormatTrait;

    /**
     * @throws SignException
     */
    public function sign(array $args): string
    {
        if (! openssl_sign($this->buildRequestMessage($args), $signature, $this->formatPrivateKey($this->getPrivateKey()), OPENSSL_ALGO_SHA256)) {
            throw new SignException('签名失败：'.(openssl_error_string() ?: '未知错误'));
        }

        return base64_encode($signature);
    }

    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool
    {
        return openssl_verify(
            $this->buildCallbackMessage($timestamp, $nonce, $data),
            base64_decode($signature),
            $this->formatPublicKey($this->getPublicKey()),
            OPENSSL_ALGO_SHA256) === 1;
    }

    public function getAlgorithmHeader(string $prefix): string
    {
        return $this->formatAlgorithmHeader($prefix, SignType::SHA256_RSA2048);
    }
}
