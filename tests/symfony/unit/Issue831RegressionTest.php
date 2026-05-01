<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Issue #831: when a Conditional Create flow is used (e.g. SimpleWebAuthn `useAutoRegister: true`),
 * the User Presence bit may legitimately be false. The bundle must let the relying party opt out of
 * the strict UP check on a per-request basis, mirroring the JS `mediation: 'conditional'` option.
 *
 * @internal
 */
final class Issue831RegressionTest extends TestCase
{
    #[Test]
    public function profileConditionalCreateFlagSetsMediationOnOptions(): void
    {
        // Backward-compat: existing profiles using the legacy boolean keep working and now produce
        // a mediation hint that flows through to CheckUserWasPresent at runtime.
        $factory = new PublicKeyCredentialCreationOptionsFactory($this->profiles(conditionalCreate: true));

        $options = $factory->create('default', $this->userEntity());

        static::assertSame(PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL, $options->mediation);
    }

    #[Test]
    public function profileWithoutConditionalCreateLeavesMediationNull(): void
    {
        $factory = new PublicKeyCredentialCreationOptionsFactory($this->profiles(conditionalCreate: false));

        $options = $factory->create('default', $this->userEntity());

        static::assertNull($options->mediation);
    }

    #[Test]
    public function explicitMediationOverridesProfileDefault(): void
    {
        $factory = new PublicKeyCredentialCreationOptionsFactory($this->profiles(conditionalCreate: true));

        $options = $factory->create(
            'default',
            $this->userEntity(),
            mediation: PublicKeyCredentialCreationOptions::MEDIATION_DEFAULT,
        );

        static::assertSame(PublicKeyCredentialCreationOptions::MEDIATION_DEFAULT, $options->mediation);
    }

    #[Test]
    public function clientOverridePolicyRejectsMediationByDefault(): void
    {
        // Out of the box, the policy is restrictive: a malicious client cannot downgrade UP enforcement
        // by sending `mediation: conditional` unless the RP explicitly enabled the override.
        $policy = new ClientOverridePolicy();

        static::assertFalse($policy->canOverride('mediation'));
        static::assertNull($policy->getEffectiveValue(
            'mediation',
            PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL,
            null,
        ));
    }

    #[Test]
    public function clientOverridePolicyHonoursMediationWhenEnabled(): void
    {
        $policy = new ClientOverridePolicy([
            'mediation' => [
                'enabled' => true,
                'allowed_values' => [
                    PublicKeyCredentialCreationOptions::MEDIATION_DEFAULT,
                    PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL,
                ],
            ],
        ]);

        static::assertSame(
            PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL,
            $policy->getEffectiveValue(
                'mediation',
                PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL,
                null,
            ),
        );
    }

    #[Test]
    public function clientOverridePolicyRejectsValueOutsideAllowedList(): void
    {
        $policy = new ClientOverridePolicy([
            'mediation' => [
                'enabled' => true,
                'allowed_values' => [PublicKeyCredentialCreationOptions::MEDIATION_DEFAULT],
            ],
        ]);

        // Even when the override is enabled, a non-allowed value falls back to the profile default.
        static::assertNull($policy->getEffectiveValue(
            'mediation',
            PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL,
            null,
        ));
    }

    #[Test]
    public function dtoAcceptsValidMediationValues(): void
    {
        $request = new PublicKeyCredentialCreationOptionsRequest();
        $request->mediation = PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL;

        static::assertSame(PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL, $request->mediation);
    }

    /**
     * @return array<string, array{rp: array{name: string, id: ?string}, challenge_length: int, attestation_conveyance: ?string, authenticator_selection_criteria: array{authenticator_attachment: ?string, user_verification: ?string, resident_key: ?string}, public_key_credential_parameters: list<int>, extensions: array<string, mixed>, conditional_create: bool}>
     */
    private function profiles(bool $conditionalCreate): array
    {
        return [
            'default' => [
                'rp' => [
                    'name' => 'Test RP',
                    'id' => null,
                ],
                'challenge_length' => 32,
                'attestation_conveyance' => null,
                'authenticator_selection_criteria' => [
                    'authenticator_attachment' => null,
                    'user_verification' => 'preferred',
                    'resident_key' => null,
                ],
                'public_key_credential_parameters' => [-7],
                'extensions' => [],
                'conditional_create' => $conditionalCreate,
            ],
        ];
    }

    private function userEntity(): PublicKeyCredentialUserEntity
    {
        return PublicKeyCredentialUserEntity::create('alice', 'uid-alice', 'Alice');
    }
}
