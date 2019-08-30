<?php
namespace LinguaLeo\Security;

use LinguaLeo\Security\Exception\SecurityException;
use LinguaLeo\Security\Exception\ValidationException;
use LinguaLeo\Security\Exception\SignatureDoesNotMatchException;
use OAuth2\Encryption\Jwt;

class JwtSerializer implements SerializerInterface
{
    private $secretKey;
    private $jwt;
    private $ttl;

    public function __construct($secretKey, $ttl)
    {
        $this->jwt = new Jwt;
        $this->secretKey = $secretKey;
        $this->ttl = $ttl;
    }

    public function serialize(CookieInterface $cookie)
    {
        if (!$cookie->isValid()) {
            throw new ValidationException('The cookie has an invalid data.');
        }
        
        return $this->jwt->encode([
            'sub' => $cookie->getId(),
            'exp' => strtotime($this->ttl),
            'typ' => 'a'
        ]);
    }

    public function unserialize(CookieInterface $cookie, $raw)
    {
        try {
            $payload = $this->jwt->decode($raw, $this->secretKey);
            if (is_array($payload)) {
                $cookie->unpack($payload);
            }
        } catch (SecurityException $e) {
            $cookie->invalidate();
            throw $e;
        }
        return $cookie;
    }
}
