<?php
namespace LinguaLeo\Security;

use LinguaLeo\Security\Exception\SecurityException;
use LinguaLeo\Security\Exception\ValidationException;
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
            'sub' => $this->uniq,
            'exp' => strtotime($this->ttl),
            'typ' => 'a'
        ]);
    }

    public function unserialize(CookieInterface $cookie, $raw)
    {
        try {
            $cookie->unpack($this->jwt->decode($raw));
        } catch (SecurityException $e) {
            $cookie->invalidate();
            throw $e;
        }
        return $cookie;
    }
}
