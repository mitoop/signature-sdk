<?php

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
    public function sign(array $args): string
    {
        try {
            $privateKey = EC::loadPrivateKey($this->getPrivateKey());

            return base64_encode($privateKey->sign($this->buildRequestMessage($args)));
        } catch (Throwable $e) {
            throw new SignException('Sign failed: '.$e->getMessage());
        }
    }

    /**
     * @throws SignException
     */
    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool
    {
        $signature = base64_decode($signature, true);

        if ($signature === false) {
            throw new SignException('Invalid base64 signature');
        }

        try {
            $publicKey = EC::loadPublicKey($this->getPublicKey());

            return $publicKey->verify($this->buildCallbackMessage($timestamp, $nonce, $data), $signature);
        } catch (Throwable $e) {
            throw new SignException('Verify failed: '.$e->getMessage());
        }

    }

    public function getAlgorithmHeader(string $prefix): string
    {
        return $this->formatAlgorithmHeader($prefix, SignType::ED25519);
    }
}
