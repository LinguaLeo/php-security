<?php

namespace LinguaLeo\Security;

interface CookieInterface
{
    public function getChecksum();

    public function pack($sig);

    public function unpack($raw);

    public function isAlive($threshold);

    public function getId();

    public function isValid();

    public function invalidate();
}