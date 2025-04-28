# Laravel Signature Sdk
SDK for [Laravel Signature](https://github.com/mitoop/laravel-signature)

## Requirements
- PHP 7.4 or higher
## Installation
To install the Laravel Signature SDK, run the following command:
```bash
composer require mitoop/laravel-signature-sdk
```

## 🚀 Quick Start

#### Using RSA Signature:
```php
use Mitoop\LaravelSignatureSdk\RsaSigner;
use Mitoop\LaravelSignatureSdk\RequestSigner;

$privateKey = 'your_private_key_string_without_BEGIN/END';
$signer = new RsaSigner($privateKey);

$requestSigner = new RequestSigner(
    mchid: 'your_merchant_id',
    appid: 'your_app_id',
    signer: $signer,
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
```

#### Using HMAC Signature:
```php
use Mitoop\LaravelSignatureSdk\HmacSigner;
use Mitoop\LaravelSignatureSdk\RequestSigner;

$secretKey = 'your_hmac_secret_key';
$signer = new HmacSigner($secretKey);

$requestSigner = new RequestSigner(
    mchid: 'your_merchant_id',
    appid: 'your_app_id',
    signer: $signer,
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
```
