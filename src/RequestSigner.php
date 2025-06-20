<?php

namespace Mitoop\SignatureSdk;

use Mitoop\SignatureSdk\Contracts\RequestSignerInterface;
use Mitoop\SignatureSdk\Contracts\SignerInterface;

class RequestSigner implements RequestSignerInterface
{
    protected string $platformPrefix;

    protected string $mchid;

    protected string $appid;

    protected SignerInterface $signer;

    public function __construct(string $mchid, string $appid, SignerInterface $signer, string $platformPrefix)
    {
        $this->mchid = $mchid;
        $this->appid = $appid;
        $this->signer = $signer;
        $this->platformPrefix = strtoupper($platformPrefix);
    }

    public function sign(string $method, string $url, ?array $data = null): string
    {
        $sign = $this->signer->sign([
            'method' => $method,
            'url' => $url,
            'data' => $data,
            'timestamp' => $timestamp = time(),
            'nonce' => $nonce = bin2hex(random_bytes(16)),
        ]);

        $authorization = sprintf(
            'mchid="%s",appid="%s",nonce="%s",timestamp="%d",sign="%s"',
            $this->mchid,
            $this->appid,
            $nonce,
            $timestamp,
            $sign
        );

        return sprintf('%s %s', $this->signer->getAlgorithmHeader($this->platformPrefix), $authorization);
    }

    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool
    {
        return $this->signer->verify($timestamp, $nonce, $data, $signature);
    }
}
