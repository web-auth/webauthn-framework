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

    /**
     * Ed256 (-260) and Ed512 (-261) sign a SHA-256 or SHA-512 digest of the payload with pure Ed25519, a construction
     * no specification defines, and IANA assigned both identifiers to unrelated algorithms. Building them emits an
     * E_USER_WARNING that the Symfony error handler turns into an exception in the dev environment.
     */
    #[Test]
    public function theNonStandardPrehashedEdDsaAlgorithmsAreNotRegistered(): void
    {
        // When
        $this->load([
            'clock' => 'system',
        ]);

        // Then
        $this->assertContainerBuilderNotHasService('webauthn.cose.algorithm.ED256');
        $this->assertContainerBuilderNotHasService('webauthn.cose.algorithm.ED512');
        $this->assertContainerBuilderHasService('webauthn.cose.algorithm.Ed25519ph');
    }

    protected function getContainerExtensions(): array
    {
        return [new WebauthnExtension('webauthn')];
    }
}
