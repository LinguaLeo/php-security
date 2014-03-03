<?php

namespace LinguaLeo\Security\Signature;

class HMACTest extends \PHPUnit_Framework_TestCase
{
    protected $hmac;

    public function setUp()
    {
        parent::setUp();
        $this->hmac = new HMAC();
    }

    public function providerSign()
    {
        return [
            ['3f8fc5b258b25102952b0c8acde50d5d653e2dc2529052be849f2dad4dfa4bc2', 'how much is the fish?', 'verysecretlongkey0'],
            ['3ab02474b84c0abb854e628fe7c349248ef048202599334ffbcf1f4d1d68cbf2', 'how old are you?', 'verysecretlongkey1'],
            ['e3207f6a3cff45604ca5379270cd1a6f1f5f69da825802755612bce8507fa2cf', 'how to create a database?', 'verysecretlongkey2'],
        ];
    }

    /**
     * @dataProvider providerSign
     */
    public function testSign($signature, $data, $key)
    {
        $this->assertSame($signature, $this->hmac->sign($data, $key));
    }

    /**
     * @dataProvider providerSign
     */
    public function testVerify($signature, $data, $key)
    {
        $this->assertTrue($this->hmac->verify($data, $signature, $key));
    }

    public function testFailedVerify()
    {
        $this->assertFalse($this->hmac->verify('foo', 'bar', 'baz'));
    }
}