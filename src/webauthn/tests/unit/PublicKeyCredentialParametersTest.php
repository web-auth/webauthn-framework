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
use function Safe\json_encode;
use Webauthn\PublicKeyCredentialParameters;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\PublicKeyCredentialParameters
 */
class PublicKeyCredentialParametersTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialParametersCanBeCreatedAndValueAccessed(): void
    {
        $parameters = new PublicKeyCredentialParameters('public-key', 100);

        static::assertEquals('public-key', $parameters->getType());
        static::assertEquals(100, $parameters->getAlg());
        static::assertEquals('{"type":"public-key","alg":100}', json_encode($parameters));

        $data = PublicKeyCredentialParameters::createFromString('{"type":"public-key","alg":100}');
        static::assertEquals('public-key', $data->getType());
        static::assertEquals(100, $data->getAlg());
        static::assertEquals('{"type":"public-key","alg":100}', json_encode($data));
    }
}
