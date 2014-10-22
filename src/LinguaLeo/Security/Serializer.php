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
            throw new SecurityException(
                'We cannot perform the signature because the cookie is invalid.',
                SecurityException::INVALID_DATA
            );
        }
        $sig = $this->signature->sign($cookie->getChecksum(), $this->secretKey);
        return $cookie->pack($sig);
    }

    public function unserialize(CookieInterface $cookie, $raw)
    {
        try {
            $this->verifyCookie($cookie,
                $this->unpackCookie($cookie,
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
            throw new SecurityException('The cookie is empty.', SecurityException::NO_DATA);
        }
        return $trimmed;
    }

    private function unpackCookie(CookieInterface $cookie, $raw)
    {
        $sig = $cookie->unpack($raw);
        if (!$cookie->isValid()) {
            throw new SecurityException(
                sprintf('We cannot perform the verification because the cookie "%s" is invalid.', $raw),
                SecurityException::INVALID_DATA
            );
        }
        return $sig;
    }

    private function verifyCookie(CookieInterface $cookie, $sig)
    {
        if (!$this->signature->verify($cookie->getChecksum(), $sig, $this->secretKey)) {
            throw new SecurityException(
                'The cookie verification is not passed.',
                SecurityException::SIGNATURE_VIOLATION
            );
        }
    }
}
