<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Functional;

/**
 * @internal
 */
final class AndroidKeyAttestationStatementTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function anAndroidKeyAttestationCanBeVerified(): void
    {
        static::markTestIncomplete(
            'This test should be finished when AAGUID "28f37d2b-92b8-41c4-b02a-860cef7cc034" will be available'
        );
    }
}
