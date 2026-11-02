<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk\Tests;

use phpseclib3\Crypt\EC;

final class Keys
{
    /**
     * @return array{0: string, 1: string}
     */
    public static function rsa(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($resource, $private);

        return [$private, openssl_pkey_get_details($resource)['key']];
    }

    /**
     * @return array{0: string, 1: string}
     */
    public static function ed25519(): array
    {
        $private = EC::createKey('Ed25519');
        $public = $private->getPublicKey();

        return [
            str_replace("\r\n", "\n", $private->toString('PKCS8')),
            str_replace("\r\n", "\n", $public->toString('PKCS8')),
        ];
    }
}
