<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service;

use const JSON_THROW_ON_ERROR;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Validator\Validation;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\WebauthnCreationOptionsResponse;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\FixedUserEntityGuesser;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\InMemoryCredentialRepository;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\InMemoryOptionsStorage;

/**
 * @internal
 */
final class WebauthnCreationOptionsResponseTest extends TestCase
{
    #[Test]
    public function buildRequiresEntityGuesser(): void
    {
        $helper = $this->helper();

        $this->expectException(LogicException::class);
        $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));
    }

    #[Test]
    public function fixedModeStoresAndSerializesTheOptionsBuiltFromTheBuilderState(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser(new FixedUserEntityGuesser($userEntity))
            ->withAuthenticatorSelectionCriteria(
                AuthenticatorSelectionCriteria::create(
                    userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                ),
            )
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT);

        $response = $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        $stored = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertInstanceOf(PublicKeyCredentialCreationOptions::class, $stored);
        static::assertSame('example.com', $stored->rp->id);
        static::assertSame('user-handle', $stored->user->id);
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $stored->authenticatorSelection?->userVerification,
        );
        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            $stored->attestation,
        );

        $payload = json_decode($response->getContent() ?: '', true, flags: JSON_THROW_ON_ERROR);
        static::assertSame('example.com', $payload['rp']['id']);
    }

    #[Test]
    public function withoutClientOverridesAllRequestFieldsAreIgnored(): void
    {
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser(new FixedUserEntityGuesser(
                PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice'),
            ))
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE);

        $clientPayload = json_encode([
            'attestation' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        ], JSON_THROW_ON_ERROR);

        $helper->build(new Request(content: $clientPayload, server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->attestation,
        );
    }

    #[Test]
    public function withClientOverridesAppliesAllowedFieldsFromTheRequestBody(): void
    {
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser(new FixedUserEntityGuesser(
                PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice'),
            ))
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
            ->withClientOverrides(new ClientOverridePolicy([
                'attestation_conveyance' => [
                    'enabled' => true,
                    'allowed_values' => [
                        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
                    ],
                ],
            ]));

        $clientPayload = json_encode([
            'attestation' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        ], JSON_THROW_ON_ERROR);

        $helper->build(new Request(content: $clientPayload, server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->attestation,
        );
    }

    #[Test]
    public function withClientOverridesRejectsValuesOutsideTheAllowedList(): void
    {
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser(new FixedUserEntityGuesser(
                PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice'),
            ))
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
            ->withClientOverrides(new ClientOverridePolicy([
                'attestation_conveyance' => [
                    'enabled' => true,
                    'allowed_values' => [PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE],
                ],
            ]));

        $clientPayload = json_encode([
            'attestation' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        ], JSON_THROW_ON_ERROR);

        $helper->build(new Request(content: $clientPayload, server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->attestation,
        );
    }

    #[Test]
    public function eachWithMethodReturnsACloneAndDoesNotMutateTheCallee(): void
    {
        $original = $this->helper();

        $derived = $original->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'));

        static::assertNotSame($original, $derived);
    }

    private function helper(?OptionsStorage $storage = null): WebauthnCreationOptionsResponse
    {
        return new WebauthnCreationOptionsResponse(
            $storage ?? new InMemoryOptionsStorage(),
            $this->serializer(),
            Validation::createValidator(),
            new InMemoryCredentialRepository(),
        );
    }

    private function serializer(): Serializer
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(NoneAttestationStatementSupport::create());

        return (new WebauthnSerializerFactory($manager))->create();
    }
}
