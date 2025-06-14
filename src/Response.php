<?php

namespace Mitoop\SignatureSdk;

use Psr\Http\Message\ResponseInterface;

class Response
{
    /**
     * @var \GuzzleHttp\Psr7\Response
     */
    protected ResponseInterface $response;

    protected array $decoded = [];

    public function __construct(ResponseInterface $response)
    {
        $this->response = $response;
    }

    public function ok()
    {
        return $this->response->getStatusCode() === 200;

    }

    public function body(): string
    {
        return (string) $this->response->getBody();
    }

    public function json($key = null, $default = null)
    {
        if (! $this->decoded) {
            $this->decoded = json_decode($this->body(), true) ?? [];
        }

        if (is_null($key)) {
            return $this->decoded;
        }

        return $this->get($this->decoded, $key, $default);
    }

    protected function get(array $data, string $key, $default = null)
    {
        foreach (explode('.', $key) as $segment) {
            if (is_array($data) && array_key_exists($segment, $data)) {
                $data = $data[$segment];
            } else {
                return $default;
            }
        }

        return $data;
    }

    public function __call($method, $parameters)
    {
        return $this->response->{$method}(...$parameters);
    }
}
