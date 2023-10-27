<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AndroidKeyAttestationStatementTest extends AbstractTestCase
{
    #[Test]
    public function anAndroidKeyAttestationCanBeVerified(): never
    {
        static::markTestIncomplete(
            'This test should be finished when AAGUID "28f37d2b-92b8-41c4-b02a-860cef7cc034" will be available'
        );
    }
}
