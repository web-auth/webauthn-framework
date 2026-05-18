<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Issue #893: dropping the deprecated `webauthn.creation_profiles.*.rp.name` node from the bundle
 * configuration (as instructed by the 5.3.0 deprecation message) made the bundle emit
 * `rp.name = ""`. SimpleWebAuthn's browser bindings refuse to call
 * `navigator.credentials.create()` when `rp.name` is empty (per W3C IDL it is required),
 * so adding authenticators to existing users silently failed. The factory now falls back to
 * the configured `rp.id` whenever the name is empty.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/893
 * @internal
 */
final class Issue893RegressionTest extends TestCase
{
    #[Test]
    public function rpNameFallsBackToRpIdWhenNameIsEmpty(): void
    {
        $factory = new PublicKeyCredentialCreationOptionsFactory($this->profiles(rpName: '', rpId: 'example.com'));

        $options = $factory->create('default', $this->userEntity());

        static::assertSame('example.com', $options->rp->name);
        static::assertSame('example.com', $options->rp->id);
    }

    #[Test]
    public function rpNameIsPreservedWhenExplicitlyConfigured(): void
    {
        $factory = new PublicKeyCredentialCreationOptionsFactory(
            $this->profiles(rpName: 'My Application', rpId: 'example.com')
        );

        $options = $factory->create('default', $this->userEntity());

        static::assertSame('My Application', $options->rp->name);
        static::assertSame('example.com', $options->rp->id);
    }

    #[Test]
    public function rpNameFallbackProducesEmptyStringWhenRpIdIsAlsoNull(): void
    {
        $factory = new PublicKeyCredentialCreationOptionsFactory($this->profiles(rpName: '', rpId: null));

        $options = $factory->create('default', $this->userEntity());

        static::assertSame('', $options->rp->name);
        static::assertNull($options->rp->id);
    }

    /**
     * @return array<string, array{rp: array{name: string, id: ?string}, challenge_length: int, attestation_conveyance: ?string, authenticator_selection_criteria: array{authenticator_attachment: ?string, user_verification: ?string, resident_key: ?string}, public_key_credential_parameters: list<int>, extensions: array<string, mixed>, conditional_create: bool}>
     */
    private function profiles(string $rpName, ?string $rpId): array
    {
        return [
            'default' => [
                'rp' => [
                    'name' => $rpName,
                    'id' => $rpId,
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
                'conditional_create' => false,
            ],
        ];
    }

    private function userEntity(): PublicKeyCredentialUserEntity
    {
        return PublicKeyCredentialUserEntity::create('alice', 'uid-alice', 'Alice');
    }
}
