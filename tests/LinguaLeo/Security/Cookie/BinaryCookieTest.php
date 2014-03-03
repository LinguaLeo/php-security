<?php

namespace LinguaLeo\Security\Cookie;

class BinaryCookieTest extends \PHPUnit_Framework_TestCase
{
    public function providerPackage()
    {
        return [
            ['01000000284f1453ac3548cfe2', 1, 1393839912, 'ac3548cfe2'],
            ['02000000304f14530d6a1d13f1', 2, 1393839920, '0d6a1d13f1'],
            ['03000000374f14536a1d13fd9e', 3, 1393839927, '6a1d13fd9e'],
            ['040000003d4f14535827057a', 4, 1393839933, '5827057a'],
        ];
    }

    /**
     * @dataProvider providerPackage
     */
    public function testPack($package, $id, $time, $sig)
    {
        $cookie = new BinaryCookie();
        $cookie->setId($id, $time);
        $this->assertSame($package, $cookie->pack($sig));
    }

    /**
     * @dataProvider providerPackage
     */
    public function testUnpack($package, $id, $time, $sig)
    {
        $cookie = new BinaryCookie();
        $this->assertSame($sig, $cookie->unpack($package));
        $this->assertSame($id, $cookie->getId());
        $this->assertTrue($cookie->isAlive($time));
    }

    public function testGetChecksum()
    {
        $id = 1;
        $now = time();
        $cookie = new BinaryCookie();
        $cookie->setId($id, $now);
        $this->assertSame($id.$now, $cookie->getChecksum());
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The identifier is empty
     */
    public function testFailedGetChecksum()
    {
        (new BinaryCookie())->getChecksum();
    }
}