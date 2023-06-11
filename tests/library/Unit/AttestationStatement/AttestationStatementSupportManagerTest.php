<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Exception\InvalidDataException;

/**
 * @internal
 */
final class AttestationStatementSupportManagerTest extends TestCase
{
    #[Test]
    public function theAttestationFormatIsNotSupported(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The attestation statement format "bar" is not supported.');
        $manager = AttestationStatementSupportManager::create();
        $manager->get('bar');
    }
}
