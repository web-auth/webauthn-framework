<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

/**
 * @group functional
 * @group Fido2
 *
 * @internal
 */
class AndroidKeyAttestationStatementTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function anAndroidKeyAttestationCanBeVerified(): void
    {
        static::markTestIncomplete('This test should be finished when AAGUID "28f37d2b-92b8-41c4-b02a-860cef7cc034" will be available');
    }
}
