<?php

namespace LinguaLeo\Security;

use LinguaLeo\Security\Signature\HMAC;
use LinguaLeo\Security\Cookie\BinaryCookie;

class SerializerTest extends \PHPUnit_Framework_TestCase
{
    private $serializer;

    public function setUp()
    {
        parent::setUp();

        $this->serializer = new Serializer(new HMAC(), 'verysecretlongkey');
    }

    public function providerPackage()
    {
        return [
            [
                '01000000797b1453cbd4d2368998e22534c23c3c7f1fa73375c2f415',
                1,
                1393851257
            ]
        ];
    }

    /**
     * @dataProvider providerPackage
     */
    public function testSerialize($package, $id, $now)
    {
        $cookie = new BinaryCookie();
        $cookie->setId($id, $now);
        $this->assertSame($package, $this->serializer->serialize($cookie));
    }

    /**
     * @dataProvider providerPackage
     */
    public function testUnserialize($package, $id, $now)
    {
        $cookie = new BinaryCookie();
        $this->assertTrue($this->serializer->unserialize($cookie, $package));
        $this->assertSame($id, $cookie->getId());
        $this->assertTrue($cookie->isAlive($now));
    }

    public function testFailedUnserialize()
    {
        $cookie = new BinaryCookie();
        $this->assertFalse($this->serializer->unserialize($cookie, md5(time())));
        $this->assertNull($cookie->getId());
    }
}