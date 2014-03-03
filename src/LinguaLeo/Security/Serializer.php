<?php

namespace LinguaLeo\Security;

class Serializer
{
    private $signature;
    private $secretKey;

    public function __construct(SignatureInterface $signature, $secretKey)
    {
        $this->signature = $signature;
        $this->secretKey = $secretKey;
    }

    public function serialize(CookieInterface $cookie)
    {
        $sig = $this->signature->sign($cookie->getChecksum(), $this->secretKey);
        return $cookie->pack($sig);
    }

    public function unserialize(CookieInterface $cookie, $raw)
    {
        $sig = $cookie->unpack($raw);
        return $this->signature->verify($cookie->getChecksum(), $sig, $this->secretKey);
    }
}