<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk;

use Mitoop\SignatureSdk\Contracts\RequestSignerInterface;
use Mitoop\SignatureSdk\Contracts\SignerInterface;
use Mitoop\SignatureSdk\Exceptions\SignException;

class RequestSigner implements RequestSignerInterface
{
    protected string $prefix;

    protected string $mchId;

    protected string $appId;

    protected SignerInterface $signer;

    /**
     * @throws SignException
     */
    public function __construct(string $mchId, string $appId, SignerInterface $signer, string $prefix)
    {
        if (strpos($prefix, '-') !== false) {
            throw new SignException('Prefix must not contain a hyphen.');
        }

        $this->mchId = $mchId;
        $this->appId = $appId;
        $this->signer = $signer;
        $this->prefix = $prefix;
    }

    public function authorization(string $method, string $url, string $body): string
    {
        $timestamp = time();
        $nonce = bin2hex(random_bytes(16));
        $sign = $this->signer->sign($method, $url, $body, $timestamp, $nonce);

        return sprintf(
            '%s mchid="%s",appid="%s",nonce="%s",timestamp="%d",sign="%s"',
            $this->signer->scheme($this->prefix),
            $this->mchId,
            $this->appId,
            $nonce,
            $timestamp,
            $sign
        );
    }

    public function verify(string $timestamp, string $nonce, string $body, string $signature): bool
    {
        return $this->signer->verify($timestamp, $nonce, $body, $signature);
    }
}
