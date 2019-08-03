<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Tests\Unit\Signature;

use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Key\Ec2Key;
use PHPUnit\Framework\TestCase;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-4.1
 *
 * @group unit
 */
class ES256KSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function es256KSignAndVerify()
    {
        $key = $this->getKey();
        $algorithm = new ES256K();
        $data = 'Hello';
        $signature = $algorithm->sign($data, $key);
        static::assertTrue($algorithm->verify($data, $key, $signature));
    }

    private function getKey(): Ec2Key
    {
        return new Ec2Key([
            Ec2Key::TYPE => 2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256K,
            Ec2Key::DATA_D => hex2bin('D1592A94BBB9B5D94CDC425FC7DA80B6A47863AE973A9D581FD9D8F29690B659'),
            Ec2Key::DATA_X => hex2bin('4B4DF318DE05BB8F3A115BF337F9BCBC55CA14B917B46BCB557D3C9A158D4BE0'),
            Ec2Key::DATA_Y => hex2bin('627EB75731A8BBEBC7D9A3C57EC4D7DA2CBA6D2A28E7F45134921861FE1CF5D9'),
        ]);
    }
}
