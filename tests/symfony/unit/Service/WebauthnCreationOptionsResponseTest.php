<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service;

use const JSON_THROW_ON_ERROR;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Validator\Validation;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\WebauthnCreationOptionsResponse;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @internal
 */
final class WebauthnCreationOptionsResponseTest extends TestCase
{
    #[Test]
    public function buildRequiresRpAndEntityGuesser(): void
    {
        $helper = $this->helper();

        $this->expectException(LogicException::class);
        $helper->build(new Request());
    }

    #[Test]
    public function fixedModeStoresAndSerializesTheOptionsBuiltFromTheBuilderState(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser($this->fixedGuesser($userEntity))
            ->withAuthenticatorSelectionCriteria(
                AuthenticatorSelectionCriteria::create(
                    userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                ),
            )
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT);

        $response = $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        $stored = $storage->last();
        static::assertInstanceOf(PublicKeyCredentialCreationOptions::class, $stored->getPublicKeyCredentialOptions());
        static::assertSame('example.com', $stored->getPublicKeyCredentialOptions()->rp->id);
        static::assertSame('user-handle', $stored->getPublicKeyCredentialOptions()->user->id);
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $stored->getPublicKeyCredentialOptions()
                ->authenticatorSelection?->userVerification,
        );
        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            $stored->getPublicKeyCredentialOptions()
                ->attestation,
        );

        $payload = json_decode($response->getContent() ?: '', true, flags: JSON_THROW_ON_ERROR);
        static::assertSame('example.com', $payload['rp']['id']);
    }

    #[Test]
    public function withoutClientOverridesAllRequestFieldsAreIgnored(): void
    {
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser($this->fixedGuesser($userEntity))
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
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser($this->fixedGuesser($userEntity))
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
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRp(PublicKeyCredentialRpEntity::create(id: 'example.com'))
            ->withEntityGuesser($this->fixedGuesser($userEntity))
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
        $rp = PublicKeyCredentialRpEntity::create(id: 'example.com');

        $derived = $original->withRp($rp);

        static::assertNotSame($original, $derived);
    }

    private function helper(?OptionsStorage $storage = null): WebauthnCreationOptionsResponse
    {
        return new WebauthnCreationOptionsResponse(
            $storage ?? new InMemoryOptionsStorage(),
            $this->serializer(),
            Validation::createValidator(),
            new EmptyCredentialRepository(),
        );
    }

    private function serializer(): Serializer
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(NoneAttestationStatementSupport::create());

        return (new WebauthnSerializerFactory($manager))->create();
    }

    private function fixedGuesser(PublicKeyCredentialUserEntity $userEntity): UserEntityGuesser
    {
        return new class($userEntity) implements UserEntityGuesser {
            public function __construct(
                private readonly PublicKeyCredentialUserEntity $userEntity,
            ) {
            }

            public function findUserEntity(Request $request): PublicKeyCredentialUserEntity
            {
                return $this->userEntity;
            }
        };
    }
}

final class InMemoryOptionsStorage implements OptionsStorage
{
    private ?Item $last = null;

    public function store(Item $item): void
    {
        $this->last = $item;
    }

    public function get(string $challenge): Item
    {
        return $this->last ?? throw new RuntimeException('No item stored.');
    }

    public function last(): Item
    {
        return $this->last ?? throw new RuntimeException('No item stored.');
    }
}

final class EmptyCredentialRepository implements CredentialRecordRepositoryInterface
{
    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        return null;
    }

    /**
     * @return array<CredentialRecord>
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return [];
    }
}
