# Signature SDK

Signature SDK 是框架无关的 PHP 签名库，用来调用 [Laravel Signature](https://github.com/mitoop/laravel-signature) 保护的 API，并验证平台回调。支持 **SHA256-RSA2048**、**SHA256-HMAC** 和 **ED25519**。

同一个商户可以有多个应用。请求和回调各有一条待签名字符串。

## 环境要求

* PHP ^7.4 || ^8.0
* ext-openssl
* ext-json
* [phpseclib](https://github.com/phpseclib/phpseclib)（仅 ED25519）

## 安装

通过 Composer 安装：

```shell
composer require mitoop/signature-sdk
```

ED25519 需要额外安装：

```shell
composer require phpseclib/phpseclib:^3.0
```

## 请求签名

商户为每个应用生成一对公私钥，私钥自己保存，公钥放到平台。请求由商户私钥签名，平台用该应用的公钥验签。`SHA256-HMAC` 没有公私钥，商户和平台共用同一把密钥。

`prefix` 是平台分配的签名前缀，不能包含连字符。`mchid` 是商户号，`appid` 是该商户下的应用号。

```php
use Mitoop\SignatureSdk\Client;
use Mitoop\SignatureSdk\RequestSigner;
use Mitoop\SignatureSdk\Signers\RsaSigner;

$signer = new RsaSigner($merchantPrivateKey, $platformPublicKey);

$requestSigner = new RequestSigner('10001', 'app_001', $signer, 'your_app');

$client = new Client([
    'base_url' => 'https://api.example.com',
], $requestSigner);

$response = $client->post('/api/payments', [
    'order_id' => '123456',
    'amount' => 100,
]);
```

`RsaSigner` 的第一个参数是商户私钥，用来给请求签名。第二个参数是平台公钥，用来验证回调。HMAC 只需要一把密钥：

```php
use Mitoop\SignatureSdk\Signers\HmacSigner;

$signer = new HmacSigner($key);
```

`your_app` 会生成这样的 `Authorization`：

```text
YOUR_APP-SHA256-RSA2048 mchid="10001",appid="app_001",nonce="abc",timestamp="1710000000",sign="base64 签名"
```

待签名字符串由请求方法、URI、时间戳、nonce 和实际发出的 JSON 正文组成。每段以 `\n` 结束，包括最后一段：

```text
POST\n
/api/payments\n
1710000000\n
abc\n
{"order_id":"123456","amount":100}\n
```

请求方法使用大写。URI 是路径和查询字符串，不包含域名。正文是实际发出的那一份 JSON。

默认校验 TLS 证书，超时 60 秒。需要调整时传入 `verify` 或 `timeout`。

## 回调验签

平台为每个商户的每个应用生成一对公私钥，或一把 HMAC 密钥。平台保存私钥，把对应的公钥交给该应用。商户用这把公钥验证回调。`SHA256-HMAC` 双方使用同一把密钥。

待签名字符串由时间戳、nonce 和回调正文组成。每段以 `\n` 结束，包括最后一段：

```text
1710000000\n
abc\n
{"order_id":"123456","status":"success"}\n
```

平台回调会带上这些请求头。`your_app` 对应：

```text
Your_app-Nonce
Your_app-Signature
Your_app-Signature-Type: YOUR_APP-SHA256-RSA2048
Your_app-Timestamp
```

取出时间戳、nonce、原始正文和签名后验证：

```php
$verified = $requestSigner->verify($timestamp, $nonce, $body, $signature);
```

验证通过后返回 HTTP `200`，正文恰好为 `success`。

## 参考

- [Laravel Signature](https://github.com/mitoop/laravel-signature)
- [微信支付 API v3](https://wechatpay-api.gitbook.io/wechatpay-api-v3)
