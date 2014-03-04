<?php

namespace LinguaLeo\Security\Cookie;

class BinaryCookieTest extends \PHPUnit_Framework_TestCase
{
    public function providerPackage()
    {
        return [
            ['a5c101000000284f1453ac3548cfe2', 1, 1393839912, 49573, 'ac3548cfe2'],
            ['7a1802000000304f14530d6a1d13f1', 2, 1393839920, 6266, '0d6a1d13f1'],
            ['e17803000000374f14536a1d13fd9e', 3, 1393839927, 30945, '6a1d13fd9e'],
            ['f4ee040000003d4f14535827057a', 4, 1393839933, 61172, '5827057a'],
        ];
    }

    /**
     * @dataProvider providerPackage
     */
    public function testPack($package, $id, $time, $salt, $sig)
    {
        $this->assertSame($package, (new BinaryCookie($id, $time, $salt))->pack($sig));
    }

    /**
     * @dataProvider providerPackage
     */
    public function testUnpack($package, $id, $time, $salt, $sig)
    {
        $cookie = new BinaryCookie();
        $this->assertSame($sig, $cookie->unpack($package));
        $this->assertTrue($cookie->isValid());
        $this->assertSame($id, $cookie->getId());
        $this->assertTrue($cookie->isAlive($time));
    }

    public function testGetChecksum()
    {
        $id = rand();
        $now = rand();
        $salt = rand();
        $cookie = new BinaryCookie($id, $now, $salt);
        $this->assertSame($id.'/'.$now.'/'.$salt, $cookie->getChecksum());
    }
}