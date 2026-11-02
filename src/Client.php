<?php

declare(strict_types=1);

namespace Mitoop\SignatureSdk;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use Mitoop\SignatureSdk\Contracts\RequestSignerInterface;
use Mitoop\SignatureSdk\Exceptions\SignException;
use Psr\Http\Message\ResponseInterface;

class Client
{
    protected string $baseUrl;

    protected ClientInterface $client;

    protected RequestSignerInterface $signer;

    /**
     * @param  array{base_url: string, timeout?: int, verify?: bool}  $config
     */
    public function __construct(array $config, RequestSignerInterface $signer, ?ClientInterface $client = null)
    {
        $this->baseUrl = rtrim($config['base_url'], '/');
        $this->signer = $signer;
        $this->client = $client ?: new GuzzleClient([
            'verify' => $config['verify'] ?? true,
            'http_errors' => false,
            'timeout' => $config['timeout'] ?? 60,
            'base_uri' => $this->baseUrl,
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
        ]);
    }

    /**
     * @throws SignException
     */
    public function post(string $url, array $data = [], array $headers = []): ResponseInterface
    {
        $body = json_encode($data);

        if ($body === false) {
            throw new SignException('JSON encoding failed.');
        }

        return $this->client->post($url, [
            'body' => $body,
            'headers' => array_merge($headers, [
                'Authorization' => $this->signer->authorization('POST', $this->fullUrl($url), $body),
            ]),
        ]);
    }

    protected function fullUrl(string $url): string
    {
        return $this->baseUrl.'/'.ltrim($url, '/');
    }
}
