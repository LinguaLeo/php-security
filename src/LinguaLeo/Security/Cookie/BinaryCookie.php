<?php

namespace LinguaLeo\Security\Cookie;

use LinguaLeo\Security\CookieInterface;

class BinaryCookie implements CookieInterface
{
    private $id;

    private $time;

    public function __construct($now = null)
    {
        if (!$now) {
            $now = time();
        }
        $this->time = $now;
    }

    public function getChecksum()
    {
        if (!$this->id) {
            throw new \RuntimeException('The identifier is empty');
        }
        return $this->id.$this->time;
    }

    public function pack($sig)
    {
        return bin2hex(pack('LLH*', $this->id, $this->time, $sig));
    }

    public function unpack($raw)
    {
        $data = unpack('Lid/Ltime/H*sig', hex2bin($raw));
        $this->id = $data['id'];
        $this->time = $data['time'];
        return $data['sig'];
    }

    public function isAlive($threshold)
    {
        return $this->time >= $threshold;
    }

    public function getId()
    {
        return $this->id;
    }

    public function setId($id)
    {
        $this->id = $id;
    }
}