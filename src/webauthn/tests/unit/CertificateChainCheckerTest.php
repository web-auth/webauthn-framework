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

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\CertificateToolbox;

/**
 * @group unit
 * @group Fido2
 */
class CertificateChainCheckerTest extends TestCase
{
    /**
     * @test
     *
     * @use \Webauthn\CertificateToolbox::checkChain
     */
    public function anCertificateChainCheckerCanBeCreatedAndValueAccessed(): void
    {
        $x5c = [
            file_get_contents(__DIR__.'/../certificates/chain/1.der'),
            file_get_contents(__DIR__.'/../certificates/chain/2.der'),
            file_get_contents(__DIR__.'/../certificates/chain/3.der'),
            file_get_contents(__DIR__.'/../certificates/chain/4.der'),
        ];
        $expected = [
            file_get_contents(__DIR__.'/../certificates/chain/1.crt'),
            file_get_contents(__DIR__.'/../certificates/chain/2.crt'),
            file_get_contents(__DIR__.'/../certificates/chain/3.crt'),
            file_get_contents(__DIR__.'/../certificates/chain/4.crt'),
        ];

        $certs = CertificateToolbox::convertAllDERToPEM($x5c);
        static::assertEquals($expected, $certs);
    }
}
