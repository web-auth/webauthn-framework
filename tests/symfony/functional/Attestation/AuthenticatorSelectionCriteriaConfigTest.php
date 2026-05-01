<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedCreationOptionsBuilder;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\LockDownAppKernel;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;

/**
 * @internal
 */
final class AuthenticatorSelectionCriteriaConfigTest extends KernelTestCase
{
    #[Test]
    public function configuredUserVerificationShouldBeRespectedWhenRequestBodyIsEmpty(): void
    {
        self::bootKernel();

        /** @var PublicKeyCredentialCreationOptionsFactory $factory */
        $factory = self::getContainer()->get(PublicKeyCredentialCreationOptionsFactory::class);

        // Create an empty request (reproduces the bug scenario)
        $emptyRequest = Request::create('/test', Request::METHOD_POST, [], [], [], [], '{}');
        $emptyRequest->headers->set('Content-Type', 'application/json');

        $builder = new ProfileBasedCreationOptionsBuilder(
            self::getContainer()->get('serializer'),
            self::getContainer()->get('validator'),
            self::getContainer()->get(PublicKeyCredentialSourceRepository::class),
            $factory,
            'default',
            self::getContainer()->get(ClientOverridePolicy::class)
        );

        $userEntity = PublicKeyCredentialUserEntity::create('test@example.com', 'test-user-id', 'Test User');

        // Get the creation options
        $options = $builder->getFromRequest($emptyRequest, $userEntity);

        // The authenticatorSelection should respect the configuration from config/config.yml
        // which sets user_verification to "preferred" (line 153 in config.yml)
        $authenticatorSelection = $options->authenticatorSelection;

        static::assertNotNull($authenticatorSelection, 'AuthenticatorSelection should not be null');
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            $authenticatorSelection->userVerification,
            'User verification should match the configured value from test config'
        );
    }

    #[Test]
    public function explicitRequestValueShouldNotOverrideConfiguration(): void
    {
        self::bootKernel();

        /** @var PublicKeyCredentialCreationOptionsFactory $factory */
        $factory = self::getContainer()->get(PublicKeyCredentialCreationOptionsFactory::class);

        $builder = new ProfileBasedCreationOptionsBuilder(
            self::getContainer()->get('serializer'),
            self::getContainer()->get('validator'),
            self::getContainer()->get(PublicKeyCredentialSourceRepository::class),
            $factory,
            'default',
            self::getContainer()->get(ClientOverridePolicy::class)
        );

        // Create a request with explicit userVerification
        $requestWithExplicitValue = Request::create(
            '/test',
            Request::METHOD_POST,
            [],
            [],
            [],
            [],
            '{"userVerification": "required"}'
        );
        $requestWithExplicitValue->headers->set('Content-Type', 'application/json');

        $userEntity = PublicKeyCredentialUserEntity::create('test@example.com', 'test-user-id', 'Test User');

        $options = $builder->getFromRequest($requestWithExplicitValue, $userEntity);

        $authenticatorSelection = $options->authenticatorSelection;
        static::assertNotNull($authenticatorSelection);

        // Profile configuration should have priority over explicit request values
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            $authenticatorSelection->userVerification,
            'Profile configuration should override explicit request values'
        );
    }

    #[Test]
    public function profileConfigurationAlwaysTakesPriority(): void
    {
        self::bootKernel();

        /** @var PublicKeyCredentialCreationOptionsFactory $factory */
        $factory = self::getContainer()->get(PublicKeyCredentialCreationOptionsFactory::class);

        $builder = new ProfileBasedCreationOptionsBuilder(
            self::getContainer()->get('serializer'),
            self::getContainer()->get('validator'),
            self::getContainer()->get(PublicKeyCredentialSourceRepository::class),
            $factory,
            'default',
            self::getContainer()->get(ClientOverridePolicy::class)
        );

        // Request with explicit values that differ from profile
        $partialRequest = Request::create(
            '/test',
            Request::METHOD_POST,
            [],
            [],
            [],
            [],
            '{"authenticatorAttachment": "cross-platform", "userVerification": "discouraged"}'
        );
        $partialRequest->headers->set('Content-Type', 'application/json');

        $userEntity = PublicKeyCredentialUserEntity::create('test@example.com', 'test-user-id', 'Test User');

        $options = $builder->getFromRequest($partialRequest, $userEntity);

        $authenticatorSelection = $options->authenticatorSelection;
        static::assertNotNull($authenticatorSelection);

        // Profile configuration should always be used, ignoring request values
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            $authenticatorSelection->userVerification,
            'Profile userVerification should override request value'
        );

        // Profile should also override authenticatorAttachment (config has 'no preference')
        static::assertSame(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            $authenticatorSelection->authenticatorAttachment,
            'Profile authenticatorAttachment should override request value'
        );
    }

    protected static function getKernelClass(): string
    {
        return LockDownAppKernel::class;
    }
}
