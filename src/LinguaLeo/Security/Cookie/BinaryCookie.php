<?php

namespace LinguaLeo\Security\Cookie;

use LinguaLeo\Security\CookieInterface;
use LinguaLeo\Security\Exception\SecurityException;

class BinaryCookie implements CookieInterface
{
    private $id;

    private $time;

    public function getChecksum()
    {
        if (!$this->id) {
            throw new SecurityException('The identifier is empty');
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

    public function setId($id, $now = null)
    {
        $this->id = $id;
        if (!$now) {
            $now = time();
        }
        $this->time = $now;
    }
}