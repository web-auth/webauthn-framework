<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorData;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\Exception\WebauthnAuthenticationFailureException;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\WebauthnAssertionVerifier;
use Webauthn\Bundle\Service\WebauthnAttestationVerifier;
use Webauthn\Bundle\Service\WebauthnResponseVerifier;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\InMemoryCredentialRepository;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\InMemoryOptionsStorage;
use Webauthn\Tests\Bundle\Unit\Service\Fixture\SaveableInMemoryCredentialRepository;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
#[AllowMockObjectsWithoutExpectations]
final class WebauthnResponseVerifierTest extends TestCase
{
    #[Test]
    public function forAttestationVerifiesAndPersistsTheCredentialRecordByDefault(): void
    {
        $rawId = 'cred-id';
        $publicKeyCredential = $this->fakeAttestationCredential($rawId);
        $repository = new SaveableInMemoryCredentialRepository();
        $storage = $this->storageWith($this->creationOptions());

        $standardValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $standardValidator->expects(static::once())
            ->method('check')
            ->willReturn($this->record($rawId));

        $conditionalValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $conditionalValidator->expects(static::never())
            ->method('check');

        $verifier = $this->verifier(
            serializer: $this->serializerReturning($publicKeyCredential),
            storage: $storage,
            repository: $repository,
            attestationValidator: $standardValidator,
            conditionalAttestationValidator: $conditionalValidator,
        );

        $result = $verifier
            ->forAttestation('example.com')
            ->verify($this->jsonRequest());

        static::assertSame($publicKeyCredential, $result->publicKeyCredential);
        static::assertTrue($repository->has($rawId), 'Credential should be persisted by default.');
    }

    #[Test]
    public function forAttestationDelegatesToConditionalValidatorWhenStoredOptionsRequestConditionalMediation(): void
    {
        $rawId = 'cred-id';
        $publicKeyCredential = $this->fakeAttestationCredential($rawId);
        $repository = new SaveableInMemoryCredentialRepository();
        $conditionalOptions = $this->creationOptions();
        $conditionalOptions->mediation = PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL;
        $storage = $this->storageWith($conditionalOptions);

        $standardValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $standardValidator->expects(static::never())->method('check');

        $conditionalValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $conditionalValidator->expects(static::once())
            ->method('check')
            ->willReturn($this->record($rawId));

        $this->verifier(
            serializer: $this->serializerReturning($publicKeyCredential),
            storage: $storage,
            repository: $repository,
            attestationValidator: $standardValidator,
            conditionalAttestationValidator: $conditionalValidator,
        )
            ->forAttestation('example.com')
            ->verify($this->jsonRequest());
    }

    #[Test]
    public function forAttestationWithSaveCredentialFalseSkipsPersistence(): void
    {
        $rawId = 'cred-id';
        $repository = new SaveableInMemoryCredentialRepository();
        $standardValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $standardValidator->method('check')
            ->willReturn($this->record($rawId));

        $this->verifier(
            serializer: $this->serializerReturning($this->fakeAttestationCredential($rawId)),
            storage: $this->storageWith($this->creationOptions()),
            repository: $repository,
            attestationValidator: $standardValidator,
        )
            ->forAttestation('example.com')
            ->withSaveCredential(false)
            ->verify($this->jsonRequest());

        static::assertFalse($repository->has($rawId));
    }

    #[Test]
    public function forAttestationRejectsDuplicateCredentials(): void
    {
        $rawId = 'cred-id';
        $repository = new SaveableInMemoryCredentialRepository([$this->record($rawId)]);
        $standardValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $standardValidator->method('check')
            ->willReturn($this->record($rawId));

        $this->expectException(WebauthnAuthenticationFailureException::class);

        $this->verifier(
            serializer: $this->serializerReturning($this->fakeAttestationCredential($rawId)),
            storage: $this->storageWith($this->creationOptions()),
            repository: $repository,
            attestationValidator: $standardValidator,
        )
            ->forAttestation('example.com')
            ->verify($this->jsonRequest());
    }

    #[Test]
    public function forAttestationRejectsNonCreationStoredOptions(): void
    {
        $this->expectException(BadRequestHttpException::class);

        $this->verifier(
            serializer: $this->serializerReturning($this->fakeAttestationCredential('cred-id')),
            storage: $this->storageWith($this->requestOptions()),
        )
            ->forAttestation('example.com')
            ->verify($this->jsonRequest());
    }

    #[Test]
    public function forAttestationRejectsRpIdMismatch(): void
    {
        $this->expectException(BadRequestHttpException::class);

        $this->verifier(
            serializer: $this->serializerReturning($this->fakeAttestationCredential('cred-id')),
            storage: $this->storageWith($this->creationOptions('other.example.com')),
        )
            ->forAttestation('example.com')
            ->verify($this->jsonRequest());
    }

    #[Test]
    public function forAttestationWrapsValidationFailuresInDedicatedException(): void
    {
        $standardValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $standardValidator->method('check')
            ->willThrowException(AuthenticatorResponseVerificationException::create('boom'));

        try {
            $this->verifier(
                serializer: $this->serializerReturning($this->fakeAttestationCredential('cred-id')),
                storage: $this->storageWith($this->creationOptions()),
                attestationValidator: $standardValidator,
            )
                ->forAttestation('example.com')
                ->verify($this->jsonRequest());

            static::fail('Expected ' . WebauthnAuthenticationFailureException::class);
        } catch (WebauthnAuthenticationFailureException $exception) {
            static::assertNotNull($exception->publicKeyCredential);
            static::assertSame('boom', $exception->getPrevious()?->getMessage());
        }
    }

    #[Test]
    public function forAssertionLoadsTheCredentialAndDelegatesToTheValidator(): void
    {
        $rawId = 'cred-id';
        $stored = $this->record($rawId);
        $repository = new InMemoryCredentialRepository([$stored]);

        $assertionValidator = $this->createMock(AuthenticatorAssertionResponseValidator::class);
        $assertionValidator->expects(static::once())
            ->method('check')
            ->with($stored)
            ->willReturn($stored);

        $result = $this->verifier(
            serializer: $this->serializerReturning($this->fakeAssertionCredential($rawId)),
            storage: $this->storageWith($this->requestOptions()),
            repository: $repository,
            assertionValidator: $assertionValidator,
        )
            ->forAssertion('example.com')
            ->verify($this->jsonRequest());

        static::assertSame($stored, $result->credentialRecord);
    }

    #[Test]
    public function forAssertionWrapsUnknownCredentialsInDedicatedException(): void
    {
        $repository = new InMemoryCredentialRepository();

        try {
            $this->verifier(
                serializer: $this->serializerReturning($this->fakeAssertionCredential('cred-id')),
                storage: $this->storageWith($this->requestOptions()),
                repository: $repository,
            )
                ->forAssertion('example.com')
                ->verify($this->jsonRequest());

            static::fail('Expected ' . WebauthnAuthenticationFailureException::class);
        } catch (WebauthnAuthenticationFailureException $exception) {
            static::assertSame('cred-id', $exception->publicKeyCredential?->rawId);
        }
    }

    #[Test]
    public function forAssertionRejectsNonRequestStoredOptions(): void
    {
        $this->expectException(BadRequestHttpException::class);

        $this->verifier(
            serializer: $this->serializerReturning($this->fakeAssertionCredential('cred-id')),
            storage: $this->storageWith($this->creationOptions()),
        )
            ->forAssertion('example.com')
            ->verify($this->jsonRequest());
    }

    #[Test]
    public function attestationRejectsNonJsonContentType(): void
    {
        $this->expectException(BadRequestHttpException::class);

        $this->verifier()
            ->forAttestation('example.com')
            ->verify(new Request(content: '{}'));
    }

    #[Test]
    public function assertionRejectsNonJsonContentType(): void
    {
        $this->expectException(BadRequestHttpException::class);

        $this->verifier()
            ->forAssertion('example.com')
            ->verify(new Request(content: '{}'));
    }

    #[Test]
    public function attestationRejectsEmptyBody(): void
    {
        $this->expectException(BadRequestHttpException::class);

        $this->verifier()
            ->forAttestation('example.com')
            ->verify($this->jsonRequest(''));
    }

    #[Test]
    public function assertionRejectsEmptyBody(): void
    {
        $this->expectException(BadRequestHttpException::class);

        $this->verifier()
            ->forAssertion('example.com')
            ->verify($this->jsonRequest(''));
    }

    #[Test]
    public function withAllowedOriginsBuildsAFreshValidatorAndBypassesTheInjectedOne(): void
    {
        $rawId = 'cred-id';
        $standardValidator = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $standardValidator->expects(static::never())
            ->method('check');

        // Real factory: when withAllowedOrigins() is set the verifier asks it
        // to produce a fresh CSM, then instantiates a fresh validator on top.
        // That fresh validator runs against the synthetic credential built in
        // the test fixture and rejects it (challenge mismatch / etc.), which
        // gets wrapped in WebauthnAuthenticationFailureException.
        $this->expectException(WebauthnAuthenticationFailureException::class);

        $this->verifier(
            serializer: $this->serializerReturning($this->fakeAttestationCredential($rawId)),
            storage: $this->storageWith($this->creationOptions()),
            attestationValidator: $standardValidator,
            factory: new CeremonyStepManagerFactory(),
        )
            ->forAttestation('example.com')
            ->withAllowedOrigins('https://app.example.com')
            ->verify($this->jsonRequest());
    }

    #[Test]
    public function withAllowedOriginsOnAssertionBypassesTheInjectedValidator(): void
    {
        $rawId = 'cred-id';
        $stored = $this->record($rawId);
        $assertionValidator = $this->createMock(AuthenticatorAssertionResponseValidator::class);
        $assertionValidator->expects(static::never())
            ->method('check');

        $this->expectException(WebauthnAuthenticationFailureException::class);

        $this->verifier(
            serializer: $this->serializerReturning($this->fakeAssertionCredential($rawId)),
            storage: $this->storageWith($this->requestOptions()),
            repository: new InMemoryCredentialRepository([$stored]),
            assertionValidator: $assertionValidator,
            factory: new CeremonyStepManagerFactory(),
        )
            ->forAssertion('example.com')
            ->withAllowedOrigins('https://app.example.com')
            ->verify($this->jsonRequest());
    }

    #[Test]
    public function forAttestationReturnsAttestationVerifier(): void
    {
        static::assertInstanceOf(
            WebauthnAttestationVerifier::class,
            $this->verifier()
                ->forAttestation('example.com')
        );
    }

    #[Test]
    public function forAssertionReturnsAssertionVerifier(): void
    {
        static::assertInstanceOf(WebauthnAssertionVerifier::class, $this->verifier() ->forAssertion('example.com'));
    }

    private function verifier(
        ?SerializerInterface $serializer = null,
        ?OptionsStorage $storage = null,
        ?CredentialRecordRepositoryInterface $repository = null,
        ?AuthenticatorAttestationResponseValidator $attestationValidator = null,
        ?AuthenticatorAttestationResponseValidator $conditionalAttestationValidator = null,
        ?AuthenticatorAssertionResponseValidator $assertionValidator = null,
        ?CeremonyStepManagerFactory $factory = null,
    ): WebauthnResponseVerifier {
        return new WebauthnResponseVerifier(
            $serializer ?? $this->realSerializer(),
            $storage ?? new InMemoryOptionsStorage(),
            $repository ?? new InMemoryCredentialRepository(),
            $attestationValidator ?? static::createStub(AuthenticatorAttestationResponseValidator::class),
            $conditionalAttestationValidator ?? static::createStub(AuthenticatorAttestationResponseValidator::class),
            $assertionValidator ?? static::createStub(AuthenticatorAssertionResponseValidator::class),
            $factory ?? new CeremonyStepManagerFactory(),
        );
    }

    private function realSerializer(): SerializerInterface
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(NoneAttestationStatementSupport::create());

        return (new WebauthnSerializerFactory($manager))->create();
    }

    private function serializerReturning(PublicKeyCredential $credential): SerializerInterface
    {
        $serializer = $this->createMock(SerializerInterface::class);
        $serializer->method('deserialize')
            ->willReturn($credential);

        return $serializer;
    }

    private function jsonRequest(string $content = '{"foo":"bar"}'): Request
    {
        return new Request(content: $content, server: [
            'CONTENT_TYPE' => 'application/json',
        ]);
    }

    private function storageWith(
        PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options,
        ?PublicKeyCredentialUserEntity $user = null,
    ): OptionsStorage {
        $storage = new InMemoryOptionsStorage();
        $storage->store(Item::create($options, $user));

        return $storage;
    }

    private function creationOptions(string $rpId = 'example.com'): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create('', $rpId),
            user: PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice'),
            challenge: random_bytes(32),
        );
    }

    private function requestOptions(string $rpId = 'example.com'): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(challenge: random_bytes(32), rpId: $rpId);
    }

    private function fakeAttestationCredential(string $rawId): PublicKeyCredential
    {
        $challenge = Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $clientData = new CollectedClientData(json_encode([
            'type' => 'webauthn.create',
            'challenge' => $challenge,
            'origin' => 'https://example.com',
        ]) ?: '', [
            'type' => 'webauthn.create',
            'challenge' => $challenge,
            'origin' => 'https://example.com',
        ]);
        $response = new AuthenticatorAttestationResponse(
            $clientData,
            static::createStub(AttestationObject::class),
            [],
        );

        return new PublicKeyCredential(
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            rawId: $rawId,
            response: $response,
        );
    }

    private function fakeAssertionCredential(string $rawId): PublicKeyCredential
    {
        $challenge = Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $clientData = new CollectedClientData(json_encode([
            'type' => 'webauthn.get',
            'challenge' => $challenge,
            'origin' => 'https://example.com',
        ]) ?: '', [
            'type' => 'webauthn.get',
            'challenge' => $challenge,
            'origin' => 'https://example.com',
        ]);
        $response = new AuthenticatorAssertionResponse(
            $clientData,
            static::createStub(AuthenticatorData::class),
            'signature',
            null,
        );

        return new PublicKeyCredential(
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            rawId: $rawId,
            response: $response,
        );
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
