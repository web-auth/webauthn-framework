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

namespace Webauthn\Tests\Unit\TrustPath;

use PHPUnit\Framework\TestCase;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;

/**
 * @group unit
 * @group Fido2
 */
class TrustPathTest extends TestCase
{
    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\CertificateTrustPath
     */
    public function aCertificateTrustPathCanBeCreated(): void
    {
        $tp = new CertificateTrustPath(['cert#1']);

        static::assertEquals(['cert#1'], $tp->getCertificates());
    }

    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\EcdaaKeyIdTrustPath
     */
    public function anEcdaaKeyIdTrustPathCanBeCreated(): void
    {
        $tp = new EcdaaKeyIdTrustPath('id');

        static::assertEquals('id', $tp->getEcdaaKeyId());
    }
}
