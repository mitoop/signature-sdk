<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Crypto;

use Mitoop\SignatureSdk\Exceptions\CryptoException;
use Mitoop\SignatureSdk\Pem;

class Rsa
{
    /**
     * @throws CryptoException
     */
    public function encrypt(string $plaintext, string $publicKey): string
    {
        if (openssl_public_encrypt($plaintext, $encrypted, Pem::format($publicKey, 'public'), OPENSSL_PKCS1_OAEP_PADDING)) {
            return base64_encode($encrypted);
        }

        throw new CryptoException('Encrypting the content failed. Please verify that the provided public key is valid.');
    }

    /**
     * @throws CryptoException
     */
    public function decrypt(string $cipherText, string $privateKey): string
    {
        $decoded = base64_decode($cipherText, true);

        if ($decoded === false) {
            throw new CryptoException('Base64 decoding failed. Invalid ciphertext.');
        }

        if (openssl_private_decrypt($decoded, $decrypted, Pem::format($privateKey, 'private'), OPENSSL_PKCS1_OAEP_PADDING)) {
            return $decrypted;
        }

        throw new CryptoException('Decrypting the content failed. Please verify that the provided private key is valid.');
    }
}
