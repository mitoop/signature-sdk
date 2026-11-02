<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Signers;

use Mitoop\SignatureSdk\Exceptions\SignException;
use phpseclib3\Crypt\EC;
use Throwable;

class Ed25519Signer extends AbstractSigner
{
    use KeyFormatTrait;

    /**
     * @throws SignException
     */
    public function sign(string $method, string $url, string $body, int $timestamp, string $nonce): string
    {
        try {
            $privateKey = EC::loadPrivateKey($this->formatPrivateKey($this->getPrivateKey()));

            return base64_encode($privateKey->sign($this->requestStringToSign($method, $url, $body, $timestamp, $nonce)));
        } catch (Throwable $e) {
            throw new SignException('Sign failed: '.$e->getMessage());
        }
    }

    /**
     * @throws SignException
     */
    public function verify(string $timestamp, string $nonce, string $body, string $signature): bool
    {
        $decoded = base64_decode($signature, true);

        if ($decoded === false) {
            return false;
        }

        try {
            $publicKey = EC::loadPublicKey($this->formatPublicKey($this->getPublicKey()));

            return $publicKey->verify($this->callbackStringToSign($timestamp, $nonce, $body), $decoded);
        } catch (Throwable $e) {
            throw new SignException('Verify failed: '.$e->getMessage());
        }
    }

    public function scheme(string $prefix): string
    {
        return strtoupper($prefix).'-'.SignType::ED25519;
    }
}
