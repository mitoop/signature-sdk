<?php

namespace Mitoop\SignatureSdk;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;

class Client
{
    protected ClientInterface $client;

    protected string $baseUrl;

    protected RequestSigner $signer;

    /**
     * @param array{
     *       base_url: string,
     *   } $config
     */
    public function __construct(array $config, RequestSigner $signer, ?ClientInterface $client = null)
    {
        $this->baseUrl = rtrim($config['base_url'], '/');
        $this->signer = $signer;
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
                'Authorization' => $this->signer->sign('POST', $this->fullUrl($url), $data),
            ]),
        ]);
    }

    protected function fullUrl(string $url): string
    {
        return rtrim($this->baseUrl, '/').'/'.ltrim($url, '/');
    }
}
