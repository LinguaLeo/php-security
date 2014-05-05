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
            ['052b22fdc0ff9f4c4f4e8c48911d9c75bba09df1', 'how much is the fish?', 'verysecretlongkey0'],
            ['a717c6c5121fd61dbaf59e623a6d53afd784fb39', 'how old are you?', 'verysecretlongkey1'],
            ['78571865eccc1c81d3f2a5294d67549451c275ba', 'how to create a database?', 'verysecretlongkey2'],
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
