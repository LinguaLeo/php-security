<?php
namespace LinguaLeo\Security\Cookie;

use LinguaLeo\Security\CookieInterface;

class JwtCookie implements CookieInterface
{
    private $sub;
    private $exp;
    private $typ;

    public function __construct($sub = null, $exp = null, $typ = null)
    {
        $this->sub = $sub;
        $this->exp = $exp;
        $this->typ = $typ;
    }

    /**
     * {@inheritdoc}
     */
    public function getChecksum()
    {
        return $this->sub;
    }

    public function getPayload(): array
    {
        return [
            'sub' => $this->sub,
            'exp' => $this->exp,
            'typ' => $this->typ,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function pack($sig)
    {
        //
    }

    /**
     * {@inheritdoc}
     */
    public function unpack($raw)
    {
        if (array_key_exists('sub', $raw)) {
            $this->sub = (int)$raw['sub'];
        }
        if (array_key_exists('exp', $raw)) {
            $this->exp = $raw['exp'];
        }
        if (array_key_exists('typ', $raw)) {
            $this->typ = $raw['typ'];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->sub;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid()
    {
        return is_int($this->sub) && $this->sub > 0;
    }

    /**
     * {@inheritdoc}
     */
    public function invalidate()
    {
        $this->sub = null;
    }
}
