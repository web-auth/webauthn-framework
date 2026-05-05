<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Validation;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\WebauthnOptionsResponse;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\FakeCredentialGenerator;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\FixedUserEntityGuesser;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\InMemoryCredentialRepository;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\InMemoryOptionsStorage;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class WebauthnOptionsResponseTest extends TestCase
{
    #[Test]
    public function forCreationProducesOptionsWithSensibleDefaultsAndStoresThem(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');

        $response = $this->helper(storage: $storage)
            ->forCreation('example.com', $userEntity)
            ->build($this->jsonRequest());

        $stored = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertInstanceOf(PublicKeyCredentialCreationOptions::class, $stored);
        static::assertSame('example.com', $stored->rp->id);
        static::assertSame('user-handle', $stored->user->id);
        static::assertNotEmpty($stored->pubKeyCredParams, 'A baseline algorithm list is set by default.');
        static::assertSame('public-key', $stored->pubKeyCredParams[0]->type);

        $payload = json_decode($response->getContent() ?: '', true, flags: JSON_THROW_ON_ERROR);
        static::assertSame('example.com', $payload['rp']['id']);
    }

    #[Test]
    public function forCreationAcceptsAGuesserResolvedAtBuildTime(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');

        $this->helper(storage: $storage)
            ->forCreation('example.com', new FixedUserEntityGuesser($userEntity))
            ->build($this->jsonRequest());

        static::assertSame('user-handle', $storage->last()->getPublicKeyCredentialOptions()->user->id);
    }

    #[Test]
    public function forCreationOverridesAreIgnoredUntilTheClientOverridePolicyIsAttached(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');

        $this->helper(storage: $storage)
            ->forCreation('example.com', $userEntity)
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
            ->build($this->jsonRequest(json_encode([
                'attestation' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            ], JSON_THROW_ON_ERROR)));

        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->attestation,
        );
    }

    #[Test]
    public function forCreationWithClientOverridesAppliesAllowedFields(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');

        $this->helper(storage: $storage)
            ->forCreation('example.com', $userEntity)
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
            ->withClientOverrides(new ClientOverridePolicy([
                'attestation_conveyance' => [
                    'enabled' => true,
                    'allowed_values' => [
                        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
                    ],
                ],
            ]))
            ->build($this->jsonRequest(json_encode([
                'attestation' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            ], JSON_THROW_ON_ERROR)));

        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->attestation,
        );
    }

    #[Test]
    public function forRequestUserlessProducesEmptyAllowCredentials(): void
    {
        $storage = new InMemoryOptionsStorage();

        $this->helper(storage: $storage)
            ->forRequest('example.com')
            ->build($this->jsonRequest());

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options);
        static::assertSame('example.com', $options->rpId);
        static::assertSame([], $options->allowCredentials);
    }

    #[Test]
    public function forRequestDerivesAllowCredentialsFromTheRepositoryWhenAUserIsPassed(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $repository = new InMemoryCredentialRepository([$this->record('cred-A'), $this->record('cred-B')]);

        $this->helper(storage: $storage, repository: $repository)
            ->forRequest('example.com')
            ->withUser($userEntity)
            ->build($this->jsonRequest());

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertCount(2, $options->allowCredentials);
        static::assertSame('cred-A', $options->allowCredentials[0]->id);
    }

    #[Test]
    public function forRequestAcceptsAGuesserAndDerivesTheDescriptorListAtBuildTime(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $repository = new InMemoryCredentialRepository([$this->record('cred-A')]);

        $this->helper(storage: $storage, repository: $repository)
            ->forRequest('example.com')
            ->withUser(new FixedUserEntityGuesser($userEntity))
            ->build($this->jsonRequest());

        static::assertCount(1, $storage->last()->getPublicKeyCredentialOptions()->allowCredentials);
    }

    #[Test]
    public function forRequestExplicitAllowCredentialsBypassesTheRepository(): void
    {
        $storage = new InMemoryOptionsStorage();
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $repository = new InMemoryCredentialRepository([$this->record('repo-cred')]);

        $this->helper(storage: $storage, repository: $repository)
            ->forRequest('example.com')
            ->withUser($userEntity)
            ->withAllowCredentials(PublicKeyCredentialDescriptor::create('public-key', 'explicit-cred'))
            ->build($this->jsonRequest());

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertCount(1, $options->allowCredentials);
        static::assertSame('explicit-cred', $options->allowCredentials[0]->id);
    }

    #[Test]
    public function forRequestUiModeAndAttestationFormatsAndHintsAreCarriedThrough(): void
    {
        $storage = new InMemoryOptionsStorage();

        $this->helper(storage: $storage)
            ->forRequest('example.com')
            ->withUiMode(PublicKeyCredentialRequestOptions::UI_MODE_IMMEDIATE)
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT)
            ->withAttestationFormats('packed', 'tpm')
            ->withHints('client-device', 'hybrid')
            ->build($this->jsonRequest());

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options);
        static::assertSame(PublicKeyCredentialRequestOptions::UI_MODE_IMMEDIATE, $options->uiMode);
        static::assertSame(['packed', 'tpm'], $options->attestationFormats);
        static::assertSame(['client-device', 'hybrid'], $options->hints);
    }

    #[Test]
    public function forRequestWithClientOverridesAppliesAllowedUserVerification(): void
    {
        $storage = new InMemoryOptionsStorage();

        $this->helper(storage: $storage)
            ->forRequest('example.com')
            ->withUserVerification(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->withClientOverrides(new ClientOverridePolicy([
                'user_verification' => [
                    'enabled' => true,
                    'allowed_values' => [
                        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                    ],
                ],
            ]))
            ->build($this->jsonRequest(json_encode([
                'userVerification' => AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            ], JSON_THROW_ON_ERROR)));

        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->userVerification,
        );
    }

    #[Test]
    public function builderSettersReturnClonesAndDoNotMutateTheReceiver(): void
    {
        $base = $this->helper()
            ->forCreation('example.com', PublicKeyCredentialUserEntity::create('alice', 'h', 'Alice'));

        $derived = $base->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT);

        static::assertNotSame($base, $derived);
    }

    #[Test]
    public function forRequestUsesTheFakeCredentialGeneratorWhenAUsernameDoesNotResolveToAUser(): void
    {
        $storage = new InMemoryOptionsStorage();
        $fakeDescriptor = PublicKeyCredentialDescriptor::create('public-key', 'fake-cred');
        $generator = new class($fakeDescriptor) implements FakeCredentialGenerator {
            public function __construct(
                private readonly PublicKeyCredentialDescriptor $descriptor,
            ) {
            }

            public function generate(Request $request, string $username): array
            {
                return [$this->descriptor];
            }
        };

        $this->helper(storage: $storage, fakeCredentialGenerator: $generator)
            ->forRequest('example.com')
            ->build($this->jsonRequest(json_encode([
                'username' => 'unknown-user',
            ], JSON_THROW_ON_ERROR)));

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertCount(1, $options->allowCredentials);
        static::assertSame('fake-cred', $options->allowCredentials[0]->id);
    }

    #[Test]
    public function forRequestProducesEmptyAllowCredentialsWhenTheBodyIsUserlessEvenIfAFakerIsActive(): void
    {
        $storage = new InMemoryOptionsStorage();
        $generator = new class() implements FakeCredentialGenerator {
            public function generate(Request $request, string $username): array
            {
                throw new RuntimeException('The fake generator MUST NOT be invoked when no username is posted.');
            }
        };

        $this->helper(storage: $storage, fakeCredentialGenerator: $generator)
            ->forRequest('example.com')
            ->build($this->jsonRequest('{}'));

        static::assertSame([], $storage->last()->getPublicKeyCredentialOptions()->allowCredentials);
    }

    #[Test]
    public function withFakeCredentialGeneratorNullOptsOutOfTheAntiEnumerationProtection(): void
    {
        $storage = new InMemoryOptionsStorage();
        $generator = new class() implements FakeCredentialGenerator {
            public function generate(Request $request, string $username): array
            {
                throw new RuntimeException('The fake generator MUST NOT be invoked once opted out.');
            }
        };

        $this->helper(storage: $storage, fakeCredentialGenerator: $generator)
            ->forRequest('example.com')
            ->withFakeCredentialGenerator(null)
            ->build($this->jsonRequest(json_encode([
                'username' => 'unknown-user',
            ], JSON_THROW_ON_ERROR)));

        static::assertSame([], $storage->last()->getPublicKeyCredentialOptions()->allowCredentials);
    }

    private function helper(
        ?OptionsStorage $storage = null,
        ?CredentialRecordRepositoryInterface $repository = null,
        ?FakeCredentialGenerator $fakeCredentialGenerator = null,
    ): WebauthnOptionsResponse {
        return new WebauthnOptionsResponse(
            $storage ?? new InMemoryOptionsStorage(),
            $this->serializer(),
            Validation::createValidator(),
            $repository ?? new InMemoryCredentialRepository(),
            $fakeCredentialGenerator,
        );
    }

    private function serializer(): Serializer
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(NoneAttestationStatementSupport::create());

        return (new WebauthnSerializerFactory($manager))->create();
    }

    private function jsonRequest(string $content = '{}'): Request
    {
        return new Request(content: $content, server: [
            'CONTENT_TYPE' => 'application/json',
        ]);
    }

    private function record(string $credentialId): CredentialRecord
    {
        return new CredentialRecord(
            publicKeyCredentialId: $credentialId,
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            transports: [],
            attestationType: AttestationStatement::TYPE_NONE,
            trustPath: EmptyTrustPath::create(),
            aaguid: Uuid::fromBinary(str_repeat("\0", 16)),
            credentialPublicKey: 'pub-key',
            userHandle: 'user-handle',
            counter: 0,
        );
    }
}
