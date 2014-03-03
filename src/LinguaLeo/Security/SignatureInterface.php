<?php

namespace LinguaLeo\Security;

interface SignatureInterface
{
    public function sign($data, $key);

    public function verify($data, $signature, $key);
}