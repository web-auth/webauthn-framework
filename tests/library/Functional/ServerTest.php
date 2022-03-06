<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use const JSON_THROW_ON_ERROR;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Server;
use Webauthn\Tests\MemoryPublicKeyCredentialSourceRepository;

/**
 * @internal
 */
final class ServerTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function theServerCanGenerateCreationOptions(): void
    {
        $server = $this->getServer();

        $userEntity = new PublicKeyCredentialUserEntity('john-doe', 'foo', 'John Doe', 'data://png:john-doe.avatar');
        $conveyanceMode = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;
        $criteria = new AuthenticatorSelectionCriteria(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            true,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
        );
        $excluded = [
            new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Uuid::v4()->__toString(),
                [
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_BLE,
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_INTERNAL,
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_NFC,
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB,
                ]
            ),
        ];
        $extensions = new AuthenticationExtensionsClientInputs();

        $options = $server->generatePublicKeyCredentialCreationOptions(
            $userEntity,
            $conveyanceMode,
            $excluded,
            $criteria,
            $extensions
        );

        static::assertSame(
            '{"name":"john-doe","icon":"data:\/\/png:john-doe.avatar","id":"Zm9v","displayName":"John Doe"}',
            json_encode($options->getUser(), JSON_THROW_ON_ERROR)
        );
        static::assertSame(
            '{"name":"rp","icon":"data:\/\/png:nice-picture","id":"foo.example"}',
            json_encode($options->getRp(), JSON_THROW_ON_ERROR)
        );
        static::assertSame('direct', $options->getAttestation());
        static::assertCount(1, $options->getExcludeCredentials());
    }

    /**
     * @test
     */
    public function theServerCanGenerateAssertionOptions(): void
    {
        $server = $this->getServer();

        $allowed = [
            new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Uuid::v4()->__toString(),
                [
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_BLE,
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_INTERNAL,
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_NFC,
                    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB,
                ]
            ),
        ];
        $extensions = new AuthenticationExtensionsClientInputs();

        $options = $server->generatePublicKeyCredentialRequestOptions(
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            $allowed,
            $extensions
        );

        static::assertSame('foo.example', $options->getRpId());
        static::assertSame(
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            $options->getUserVerification()
        );
        static::assertCount(1, $options->getAllowCredentials());
        static::assertSame(60000, $options->getTimeout());
    }

    private function getServer(): Server
    {
        $rpEntity = new PublicKeyCredentialRpEntity('rp', 'foo.example', 'data://png:nice-picture');
        $pkRepository = $this->getPublicKeyCredentialRepository();

        return new Server($rpEntity, $pkRepository);
    }

    private function getPublicKeyCredentialRepository(): MemoryPublicKeyCredentialSourceRepository
    {
        $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            'foo',
            100,
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            base64_decode(
                'pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=',
                true
            )
        );
        $repository = new MemoryPublicKeyCredentialSourceRepository();
        $repository->saveCredentialSource($publicKeyCredentialSource);

        return $repository;
    }
}
