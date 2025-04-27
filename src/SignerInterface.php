<?php

namespace Mitoop\LaravelSignatureSdk;

interface SignerInterface
{
    public function sign(array $args): string;
}
