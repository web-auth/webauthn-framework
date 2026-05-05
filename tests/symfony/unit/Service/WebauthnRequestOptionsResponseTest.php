<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service;

use const JSON_THROW_ON_ERROR;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Validation;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\WebauthnRequestOptionsResponse;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
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
final class WebauthnRequestOptionsResponseTest extends TestCase
{
    #[Test]
    public function buildRequiresRpId(): void
    {
        $helper = $this->helper();

        $this->expectException(LogicException::class);
        $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));
    }

    #[Test]
    public function userlessAssertionProducesEmptyAllowCredentialsByDefault(): void
    {
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRpId('example.com');

        $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options);
        static::assertSame('example.com', $options->rpId);
        static::assertSame([], $options->allowCredentials);
    }

    #[Test]
    public function deriveAllowCredentialsFromUserPullsTheDescriptorListFromTheRepository(): void
    {
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $repository = new InMemoryCredentialRepository([$this->record('cred-A'), $this->record('cred-B')]);
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage, repository: $repository)
            ->withRpId('example.com')
            ->withEntityGuesser(new FixedUserEntityGuesser($userEntity));

        $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options);
        static::assertCount(2, $options->allowCredentials);
        static::assertSame('cred-A', $options->allowCredentials[0]->id);
        static::assertSame('cred-B', $options->allowCredentials[1]->id);
    }

    #[Test]
    public function withAllowCredentialsHonoursTheExplicitDescriptorListAndIgnoresTheRepository(): void
    {
        $userEntity = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $repository = new InMemoryCredentialRepository([$this->record('repo-cred')]);
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage, repository: $repository)
            ->withRpId('example.com')
            ->withEntityGuesser(new FixedUserEntityGuesser($userEntity))
            ->withAllowCredentials(PublicKeyCredentialDescriptor::create('public-key', 'explicit-cred'));

        $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertCount(1, $options->allowCredentials);
        static::assertSame('explicit-cred', $options->allowCredentials[0]->id);
    }

    #[Test]
    public function withoutClientOverridesAllRequestFieldsAreIgnored(): void
    {
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRpId('example.com')
            ->withUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED);

        $clientPayload = json_encode([
            'userVerification' => PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        ], JSON_THROW_ON_ERROR);

        $helper->build(new Request(content: $clientPayload, server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        static::assertSame(
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->userVerification,
        );
    }

    #[Test]
    public function withClientOverridesAppliesAllowedFieldsFromTheRequestBody(): void
    {
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRpId('example.com')
            ->withUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->withClientOverrides(new ClientOverridePolicy([
                'user_verification' => [
                    'enabled' => true,
                    'allowed_values' => [
                        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                    ],
                ],
            ]));

        $clientPayload = json_encode([
            'userVerification' => PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        ], JSON_THROW_ON_ERROR);

        $helper->build(new Request(content: $clientPayload, server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        static::assertSame(
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $storage->last()
                ->getPublicKeyCredentialOptions()
                ->userVerification,
        );
    }

    #[Test]
    public function uiModeAndAttestationFormatsAndHintsAreCarriedThrough(): void
    {
        $storage = new InMemoryOptionsStorage();

        $helper = $this->helper(storage: $storage)
            ->withRpId('example.com')
            ->withUiMode(PublicKeyCredentialRequestOptions::UI_MODE_IMMEDIATE)
            ->withAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT)
            ->withAttestationFormats('packed', 'tpm')
            ->withHints('client-device', 'hybrid');

        $helper->build(new Request(content: '{}', server: [
            'CONTENT_TYPE' => 'application/json',
        ]));

        $options = $storage->last()
            ->getPublicKeyCredentialOptions();
        static::assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options);
        static::assertSame(PublicKeyCredentialRequestOptions::UI_MODE_IMMEDIATE, $options->uiMode);
        static::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            $options->attestation,
        );
        static::assertSame(['packed', 'tpm'], $options->attestationFormats);
        static::assertSame(['client-device', 'hybrid'], $options->hints);
    }

    #[Test]
    public function eachWithMethodReturnsACloneAndDoesNotMutateTheCallee(): void
    {
        $original = $this->helper();

        $derived = $original->withRpId('example.com');

        static::assertNotSame($original, $derived);
    }

    private function helper(
        ?OptionsStorage $storage = null,
        ?CredentialRecordRepositoryInterface $repository = null,
    ): WebauthnRequestOptionsResponse {
        return new WebauthnRequestOptionsResponse(
            $storage ?? new InMemoryOptionsStorage(),
            $this->serializer(),
            Validation::createValidator(),
            $repository ?? new InMemoryCredentialRepository(),
        );
    }

    private function serializer(): Serializer
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(NoneAttestationStatementSupport::create());

        return (new WebauthnSerializerFactory($manager))->create();
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
