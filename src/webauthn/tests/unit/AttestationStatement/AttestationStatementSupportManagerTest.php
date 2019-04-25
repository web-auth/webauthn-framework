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

namespace Webauthn\Tests\Unit\AttestationStatement;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\AttestationStatementSupportManager
 */
class AttestationStatementSupportManagerTest extends TestCase
{
    /**
     * @test
     */
    public function theAttestationFormatIsNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement format "bar" is not supported.');
        $manager = new AttestationStatementSupportManager();
        $manager->get('bar');
    }
}
