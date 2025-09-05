<?php

use Mitoop\SignatureSdk\Exceptions\SignException;

class AesGcm
{
    public const ALGO = 'aes-256-gcm';

    public const TAG_LENGTH = 16;

    /**
     * @throws SignException
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
            throw new SignException('Encrypting the input $plaintext failed, please check your key and IV.');
        }

        return [
            'ciphertext' => base64_encode($ciphertext.$tag),
            'iv' => base64_encode($iv),
            'associated_data' => $associatedData,
        ];
    }

    /**
     * @throws SignException
     */
    public function decrypt(
        string $ciphertext,
        string $key,
        string $iv,
        string $associatedData = ''
    ): string {
        $decodedCiphertext = base64_decode($ciphertext, true);
        if ($decodedCiphertext === false) {
            throw new SignException('Base64 decoding failed. Invalid ciphertext.');
        }
        if (strlen($decodedCiphertext) < self::TAG_LENGTH) {
            throw new SignException('Ciphertext too short, cannot extract auth tag.');
        }
        $tag = substr($decodedCiphertext, -self::TAG_LENGTH);
        $cipherData = substr($decodedCiphertext, 0, -self::TAG_LENGTH);

        $plaintext = openssl_decrypt($cipherData, static::ALGO, $key, OPENSSL_RAW_DATA, $iv, $tag, $associatedData);

        if ($plaintext === false) {
            throw new SignException('Decrypting the input $ciphertext failed, please checking your $key and $iv whether or nor correct.');
        }

        return $plaintext;
    }
}
