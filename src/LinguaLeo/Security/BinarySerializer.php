<?php
namespace LinguaLeo\Security;

use LinguaLeo\Security\Exception\SecurityException;
use LinguaLeo\Security\Exception\ValidationException;
use LinguaLeo\Security\Exception\SignatureDoesNotMatchException;

class BinarySerializer implements SerializerInterface
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
            throw new ValidationException('The cookie has an invalid data.');
        }
        $sig = $this->signature->sign($cookie->getChecksum(), $this->secretKey);
        return $cookie->pack($sig);
    }

    public function unserialize(CookieInterface $cookie, $raw)
    {
        try {
            $this->verifyCookie(
                $cookie,
                $this->unpackCookie(
                    $cookie,
                    $this->prepareRaw($raw)
                )
            );
        } catch (SecurityException $e) {
            $cookie->invalidate();
            throw $e;
        }
        return $cookie;
    }

    private function prepareRaw($raw)
    {
        $trimmed = trim($raw);
        if (!$trimmed) {
            throw new ValidationException('The cookie is empty.');
        }
        return $trimmed;
    }

    private function unpackCookie(CookieInterface $cookie, $raw)
    {
        $sig = $cookie->unpack($raw);
        if (!$cookie->isValid()) {
            throw new ValidationException(
                sprintf('The cookie "%s" has an invalid format.', $raw)
            );
        }
        return $sig;
    }

    private function verifyCookie(CookieInterface $cookie, $sig)
    {
        if (!$this->signature->verify($cookie->getChecksum(), $sig, $this->secretKey)) {
            throw new SignatureDoesNotMatchException('The signature verification is not passed.');
        }
    }
}
