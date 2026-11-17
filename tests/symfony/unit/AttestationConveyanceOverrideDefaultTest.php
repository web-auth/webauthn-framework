<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Processor;
use Webauthn\Bundle\DependencyInjection\Configuration;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\PublicKeyCredentialCreationOptions;

/**
 * With the default client override policy, a creation profile that requests attestation keeps it: the client cannot
 * ask for the "none" conveyance, under which the attestation statement is not verified. It can still ask for another
 * conveyance, and every one of them is verified.
 *
 * @internal
 */
final class AttestationConveyanceOverrideDefaultTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function profileConveyancesThatRequestAttestation(): iterable
    {
        yield 'indirect' => [PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT];
        yield 'direct' => [PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT];
        yield 'enterprise' => [PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE];
    }

    #[Test]
    #[DataProvider('profileConveyancesThatRequestAttestation')]
    public function theClientCannotWaiveTheAttestationTheProfileRequests(string $profileConveyance): void
    {
        static::assertSame(
            $profileConveyance,
            self::defaultPolicy()->getEffectiveValue(
                'attestation_conveyance',
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                $profileConveyance
            )
        );
    }

    #[Test]
    public function theClientCanStillAskForAnotherVerifiedConveyance(): void
    {
        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE,
            self::defaultPolicy()->getEffectiveValue(
                'attestation_conveyance',
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE,
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
            )
        );
    }

    private static function defaultPolicy(): ClientOverridePolicy
    {
        $config = (new Processor())->processConfiguration(new Configuration('webauthn'), []);

        return new ClientOverridePolicy($config['client_override_policy']);
    }
}
