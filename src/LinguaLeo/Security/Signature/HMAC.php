<?php
namespace LinguaLeo\Security\Signature;

use LinguaLeo\Security\SignatureInterface;

class HMAC implements SignatureInterface
{
    private $algo;

    public function __construct($algo = 'sha1')
    {
        $this->algo = $algo;
    }

    public function sign($data, $key)
    {
        return hash_hmac($this->algo, $data, $key);
    }

    public function verify($data, $signature, $key)
    {
        return $this->sign($data, $key) === $signature;
    }
}
