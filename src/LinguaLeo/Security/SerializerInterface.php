<?php
namespace LinguaLeo\Security;

interface SerializerInterface {
    public function serialize(CookieInterface $cookie);

    public function unserialize(CookieInterface $cookie, $raw);
}