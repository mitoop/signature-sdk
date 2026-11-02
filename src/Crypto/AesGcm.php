<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Crypto;

use Mitoop\SignatureSdk\Exceptions\CryptoException;

class AesGcm
{
    public const ALGO = 'aes-256-gcm';

    public const TAG_LENGTH = 16;

    /**
     * @throws CryptoException
     */
    public function encrypt(string $plaintext, string $key, string $associatedData = ''): array
    {
        $iv = random_bytes(openssl_cipher_iv_length(static::ALGO));

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            static::ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $associatedData,
            static::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new CryptoException('Encrypting the plaintext failed.');
        }

        return [
            'ciphertext' => base64_encode($ciphertext.$tag),
            'iv' => base64_encode($iv),
            'associated_data' => $associatedData,
        ];
    }

    /**
     * @throws CryptoException
     */
    public function decrypt(string $ciphertext, string $key, string $iv, string $associatedData = ''): string
    {
        $decodedCiphertext = base64_decode($ciphertext, true);

        if ($decodedCiphertext === false) {
            throw new CryptoException('Base64 decoding failed. Invalid ciphertext.');
        }

        if (strlen($decodedCiphertext) < self::TAG_LENGTH) {
            throw new CryptoException('Ciphertext too short, cannot extract auth tag.');
        }

        $tag = substr($decodedCiphertext, -self::TAG_LENGTH);
        $cipherData = substr($decodedCiphertext, 0, -self::TAG_LENGTH);
        $decodedIv = base64_decode($iv, true);
        $expectedIvLength = openssl_cipher_iv_length(static::ALGO);

        if ($decodedIv === false || strlen($decodedIv) !== $expectedIvLength) {
            throw new CryptoException('Base64 decoding failed. Invalid IV.');
        }

        $plaintext = openssl_decrypt($cipherData, static::ALGO, $key, OPENSSL_RAW_DATA, $decodedIv, $tag, $associatedData);

        if ($plaintext === false) {
            throw new CryptoException('Decrypting the ciphertext failed.');
        }

        return $plaintext;
    }
}
