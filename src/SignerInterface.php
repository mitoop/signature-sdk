<?php

namespace Mitoop\SignatureSdk;

interface SignerInterface
{
    public function sign(array $args): string;
}
