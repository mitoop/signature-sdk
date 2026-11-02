<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Crypto;

use Mitoop\SignatureSdk\Exceptions\CryptoException;
use Mitoop\SignatureSdk\Pem;

class RsaAesGcm
{
    public const ALGO = 'aes-256-gcm';

    public const AES_KEY_SIZE = 32;

    public const TAG_LENGTH = 16;

    /**
     * @throws CryptoException
     */
    public function encrypt(string $plainText, string $rsaPublicKey, string $associatedData = ''): array
    {
        $aesKey = random_bytes(self::AES_KEY_SIZE);

        if (! openssl_public_encrypt($aesKey, $encryptedKey, Pem::format($rsaPublicKey, 'public'), OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new CryptoException('RSA encrypt AES key failed. Please check the public key.');
        }

        $iv = random_bytes(openssl_cipher_iv_length(self::ALGO));
        $tag = '';
        $cipherText = openssl_encrypt(
            $plainText,
            self::ALGO,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $associatedData,
            self::TAG_LENGTH
        );

        if ($cipherText === false) {
            throw new CryptoException('AES-GCM encrypt data failed.');
        }

        return [
            'encrypted_key' => base64_encode($encryptedKey),
            'iv' => base64_encode($iv),
            'ciphertext' => base64_encode($cipherText.$tag),
            'associated_data' => $associatedData,
        ];
    }

    /**
     * @throws CryptoException
     */
    public function decrypt(
        string $encryptedKey,
        string $ciphertext,
        string $rsaPrivateKey,
        string $iv,
        string $associatedData = ''
    ): string {
        $decodedEncryptedKey = base64_decode($encryptedKey, true);

        if ($decodedEncryptedKey === false) {
            throw new CryptoException('Invalid base64 for encrypted_key.');
        }

        if (! openssl_private_decrypt($decodedEncryptedKey, $aesKey, Pem::format($rsaPrivateKey, 'private'), OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new CryptoException('RSA decrypt AES key failed. Please check the private key.');
        }

        $decodedCiphertext = base64_decode($ciphertext, true);

        if ($decodedCiphertext === false) {
            throw new CryptoException('Invalid base64 for ciphertext.');
        }

        if (strlen($decodedCiphertext) < self::TAG_LENGTH) {
            throw new CryptoException('Ciphertext too short, cannot extract auth tag.');
        }

        $tag = substr($decodedCiphertext, -self::TAG_LENGTH);
        $cipherData = substr($decodedCiphertext, 0, -self::TAG_LENGTH);
        $decodedIv = base64_decode($iv, true);
        $expectedIvLength = openssl_cipher_iv_length(self::ALGO);

        if ($decodedIv === false || strlen($decodedIv) !== $expectedIvLength) {
            throw new CryptoException('Invalid base64 for iv.');
        }

        $plainText = openssl_decrypt(
            $cipherData,
            self::ALGO,
            $aesKey,
            OPENSSL_RAW_DATA,
            $decodedIv,
            $tag,
            $associatedData
        );

        if ($plainText === false) {
            throw new CryptoException('AES-GCM decrypt data failed.');
        }

        return $plainText;
    }
}
