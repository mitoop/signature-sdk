<?php

namespace Mitoop\SignatureSdk\Signers;

use Mitoop\SignatureSdk\Contracts\SignerInterface;

abstract class AbstractSigner implements SignerInterface
{
    protected function buildRequestMessage(array $args): string
    {
        $urlPath = parse_url($args['url'], PHP_URL_PATH);
        $urlQuery = parse_url($args['url'], PHP_URL_QUERY);

        return strtoupper($args['method'])."\n".
            $urlPath.(empty($urlQuery) ? '' : '?'.$urlQuery)."\n".
            $args['timestamp']."\n".
            $args['nonce']."\n".
            ($args['data'] ? json_encode($args['data']) : '')."\n";
    }

    protected function buildCallbackMessage($timestamp, $nonce, $data): string
    {
        return $timestamp."\n".
             $nonce."\n".
             $data."\n";
    }

    protected function formatAlgorithmHeader(string $prefix, string $signType): string
    {
        return sprintf('%s-%s', $prefix, $signType);
    }
}
