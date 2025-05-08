# Signature Sdk
Signature SDK is a framework-agnostic PHP library that provides secure request signing and verification logic.
It is the core signing engine used by laravel-signature, but can also be used independently in any PHP project.

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

$privateKey = 'your_rsa_private_key_string_without_BEGIN/END';

$requestSigner = new RequestSigner(
    mchid: 'your_merchant_id',
    appid: 'your_app_id',
    signer: new RsaSigner($privateKey),
    platformPrefix: 'XXX' // Platform prefix
);

$authorization = $requestSigner->generateAuthorization(
    method: 'POST',
    url: 'https://api.example.com/v1/pay',
    data: [
        'amount' => 100,
        'currency' => 'USD'
    ]
);

// Initialize Guzzle client
$client = new Client();

$response = $client->post('https://api.example.com/v1/pay', [
    'json' => [
        'amount' => 100,
        'currency' => 'USD',
    ],
    'headers' => [
        'Authorization' => $authorization,
        'Accept' => 'application/json',
    ]
]);

echo $response->getBody()->getContents();
```
