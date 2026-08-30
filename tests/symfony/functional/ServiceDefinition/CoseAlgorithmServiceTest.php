<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\ServiceDefinition;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractExtensionTestCase;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;

/**
 * @internal
 */
final class CoseAlgorithmServiceTest extends AbstractExtensionTestCase
{
    /**
     * RS1 relies on SHA-1, which is no longer acceptable for digital signatures, and building it emits an
     * E_USER_WARNING that the Symfony error handler turns into an exception in the dev environment. The applications
     * that still have to verify the credentials of legacy authenticators declare the service themselves.
     */
    #[Test]
    public function theInsecureRs1AlgorithmIsNotRegistered(): void
    {
        // When
        $this->load([
            'clock' => 'system',
        ]);

        // Then
        $this->assertContainerBuilderNotHasService('webauthn.cose.algorithm.RS1');
        $this->assertContainerBuilderHasService('webauthn.cose.algorithm.RS256');
    }

    protected function getContainerExtensions(): array
    {
        return [new WebauthnExtension('webauthn')];
    }
}
