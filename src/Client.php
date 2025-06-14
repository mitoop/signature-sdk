<?php

namespace Mitoop\SignatureSdk;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;

class Client
{
    protected string $mchid;

    protected string $appid;

    protected string $platformPrefix;

    protected ClientInterface $client;

    protected string $baseUrl;

    protected RequestSigner $requestSigner;

    /**
     * @param array{
     *       mchid: string|int,
     *       appid: string|int,
     *       base_url: string,
     *       platform_prefix: string,
     *   } $config
     */
    public function __construct(array $config, SignerInterface $signer, ?ClientInterface $client = null)
    {
        $this->mchid = $config['mchid'];
        $this->appid = $config['appid'];
        $this->baseUrl = rtrim($config['base_url'], '/');
        $this->platformPrefix = strtoupper($config['platform_prefix']);
        $this->requestSigner = new RequestSigner($this->mchid, $this->appid, $signer, $this->platformPrefix);
        $this->client = $client ?: new GuzzleClient([
            'verify' => false,
            'http_errors' => false,
            'timeout' => 120,
            'base_uri' => $this->baseUrl,
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
        ]);
    }

    public function post($url, array $data, array $headers = [])
    {
        return $this->client->post($url, [
            'json' => $data,
            'headers' => array_merge($headers, [
                'Authorization' => $this->requestSigner->sign('POST', $this->fullUrl($url), $data),
            ]),
        ]);
    }

    protected function fullUrl(string $url): string
    {
        return rtrim($this->baseUrl, '/').'/'.ltrim($url, '/');
    }
}
