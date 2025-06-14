# Signature Sdk
Signature SDK is a framework-agnostic PHP library that provides secure request signing and verification logic.
It is the core signing engine used by [laravel-signature](https://github.com/mitoop/laravel-signature).

## Requirements
- PHP 7.4 or higher
- OpenSSL extension enabled

## Installation
Install via Composer:
```bash
composer require mitoop/signature-sdk
```

## 🚀 Quick Start

#### 🔐 Using RSA Signature:
```php
use Mitoop\SignatureSdk\RsaSigner;
use Mitoop\SignatureSdk\RequestSigner;
use Mitoop\SignatureSdk\Client;
$privateKey = 'your_rsa_private_key_string';
$publicKey = 'plat_rsa_public_key_string';

$signer = new RsaSigner($privateKey, $publicKey);

$requestSigner = new RequestSigner(
    mchid: 'your_merchant_id',
    appid: 'your_app_id',
    signer: $signer,
    platformPrefix: 'MP' // Paltform prefix
);

$client = new Client(
    config: [
        'base_url' => 'https://api.example.com',
    ],
    signer: $requestSigner
);

$response = $client->post('/v1/pay', [
    'amount' => 100,
    'currency' => 'USD',
]);

$data = json_decode((string) $response->getBody(), true);

print_r($data);
```
