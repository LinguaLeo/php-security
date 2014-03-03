<?php

namespace LinguaLeo\Security\Cookie;

use LinguaLeo\Security\CookieInterface;

class BinaryCookie implements CookieInterface
{
    private $id;

    private $ts;

    public function __construct($id = null, $ts = null)
    {
        $this->id = $id;
        $this->ts = $ts;
    }

    public function getChecksum()
    {
        return $this->id.$this->ts;
    }

    public function pack($sig)
    {
        return bin2hex(pack('LLH*', $this->id, $this->ts, $sig));
    }

    public function unpack($raw)
    {
        $data = unpack('Lid/Lts/H*sig', hex2bin($raw));
        $this->id = $data['id'];
        $this->ts = $data['ts'];
        return $data['sig'];
    }

    public function isAlive($threshold)
    {
        return $this->ts >= $threshold;
    }

    public function getId()
    {
        return $this->id;
    }

    public function isValid()
    {
        return $this->id > 0 && $this->ts > 0;
    }

    public function invalidate()
    {
        $this->id = null;
        $this->ts = null;
    }
}