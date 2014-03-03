<?php

namespace LinguaLeo\Security;

use LinguaLeo\Security\Exception\SecurityException;

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
        if (!$cookie->isValid()) {
            throw new SecurityException('We cannot perform the signature because the cookie is invalid.');
        }
        $sig = $this->signature->sign($cookie->getChecksum(), $this->secretKey);
        return $cookie->pack($sig);
    }

    public function unserialize(CookieInterface $cookie, $raw)
    {
        $sig = $cookie->unpack($raw);
        if (!$cookie->isValid()) {
            throw new SecurityException(sprintf('We cannot perform the verification because the cookie "%s" is invalid.', $raw));
        }
        if (!$this->signature->verify($cookie->getChecksum(), $sig, $this->secretKey)) {
            $cookie->invalidate();
        }
        return $cookie;
    }
}