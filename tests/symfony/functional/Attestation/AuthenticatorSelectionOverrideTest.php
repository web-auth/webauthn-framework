<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedCreationOptionsBuilder;
use Webauthn\Bundle\DependencyInjection\Configuration;
use Webauthn\Bundle\Event\PublicKeyCredentialCreationOptionsCreatedEvent;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;

/**
 * A client that overrides one member of the authenticator selection criteria of a creation profile only changes that
 * member: the other members, user verification included, keep the value of the profile. Before the fix, sending the
 * authenticator attachment or the resident key with the default policy replaced the whole criteria of the profile and
 * reset user verification to "preferred" (GHSA-2989-5cjp-qc2p).
 *
 * @internal
 */
final class AuthenticatorSelectionOverrideTest extends KernelTestCase
{
    /**
     * @return iterable<string, array{string, ?string, string, ?string}>
     */
    public static function requestsUnderTheDefaultPolicy(): iterable
    {
        yield 'empty request' => [
            '{}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        ];
        yield 'user verification' => [
            '{"userVerification": "discouraged"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        ];
        yield 'authenticator attachment' => [
            '{"authenticatorAttachment": "cross-platform"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        ];
        yield 'resident key' => [
            '{"residentKey": "discouraged"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
        ];
        yield 'every member' => [
            '{"authenticatorAttachment": "platform", "userVerification": "preferred", "residentKey": "preferred"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        ];
    }

    /**
     * @return iterable<string, array{string, ?string, string, ?string}>
     */
    public static function requestsUnderARestrictivePolicy(): iterable
    {
        yield 'allowed user verification' => [
            '{"userVerification": "preferred"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        ];
        yield 'user verification not allowed' => [
            '{"userVerification": "discouraged"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        ];
        yield 'authenticator attachment override disabled' => [
            '{"authenticatorAttachment": "cross-platform"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        ];
        yield 'allowed resident key' => [
            '{"residentKey": "required"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        ];
        yield 'resident key not allowed' => [
            '{"residentKey": "discouraged"}',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        ];
    }

    #[Test]
    #[DataProvider('requestsUnderTheDefaultPolicy')]
    public function theDefaultPolicyNeverResetsTheUserVerificationOfTheProfile(
        string $body,
        ?string $expectedAuthenticatorAttachment,
        string $expectedUserVerification,
        ?string $expectedResidentKey,
    ): void {
        $factory = self::factory(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
        );

        $options = $this->optionsFor($body, $factory, self::defaultPolicy());

        self::assertCriteria(
            $options,
            $expectedAuthenticatorAttachment,
            $expectedUserVerification,
            $expectedResidentKey
        );
    }

    #[Test]
    #[DataProvider('requestsUnderARestrictivePolicy')]
    public function onlyTheMembersThePolicyAllowsAreTakenFromTheClient(
        string $body,
        ?string $expectedAuthenticatorAttachment,
        string $expectedUserVerification,
        ?string $expectedResidentKey,
    ): void {
        $factory = self::factory(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED
        );
        $policy = new ClientOverridePolicy([
            'user_verification' => [
                'enabled' => true,
                'allowed_values' => [
                    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                ],
            ],
            'authenticator_attachment' => [
                'enabled' => false,
            ],
            'resident_key' => [
                'enabled' => true,
                'allowed_values' => [
                    AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
                    AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
                ],
            ],
        ]);

        $options = $this->optionsFor($body, $factory, $policy);

        self::assertCriteria(
            $options,
            $expectedAuthenticatorAttachment,
            $expectedUserVerification,
            $expectedResidentKey
        );
    }

    #[Test]
    public function theListenersOfTheCreatedEventSeeTheMergedCriteria(): void
    {
        $eventDispatcher = new class() implements EventDispatcherInterface {
            /**
             * @var list<object>
             */
            public array $events = [];

            public function dispatch(object $event): object
            {
                $this->events[] = $event;

                return $event;
            }
        };
        $factory = self::factory(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
        );
        $factory->setEventDispatcher($eventDispatcher);

        $options = $this->optionsFor('{"authenticatorAttachment": "cross-platform"}', $factory, self::defaultPolicy());

        static::assertCount(1, $eventDispatcher->events);
        $event = $eventDispatcher->events[0];
        static::assertInstanceOf(PublicKeyCredentialCreationOptionsCreatedEvent::class, $event);
        static::assertSame($options, $event->publicKeyCredentialCreationOptions);
        self::assertCriteria(
            $event->publicKeyCredentialCreationOptions,
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
        );
    }

    private function optionsFor(
        string $body,
        PublicKeyCredentialCreationOptionsFactory $factory,
        ClientOverridePolicy $policy,
    ): PublicKeyCredentialCreationOptions {
        self::bootKernel();
        $container = self::getContainer();
        $serializer = $container->get('serializer');
        static::assertInstanceOf(SerializerInterface::class, $serializer);
        $validator = $container->get('validator');
        static::assertInstanceOf(ValidatorInterface::class, $validator);
        $credentialRecordRepository = $container->get(PublicKeyCredentialSourceRepository::class);
        static::assertInstanceOf(PublicKeyCredentialSourceRepository::class, $credentialRecordRepository);

        $builder = new ProfileBasedCreationOptionsBuilder(
            $serializer,
            $validator,
            $credentialRecordRepository,
            $factory,
            'strict',
            $policy
        );
        $request = Request::create('/attestation/options', Request::METHOD_POST, [], [], [], [], $body);
        $request->headers->set('Content-Type', 'application/json');

        return $builder->getFromRequest(
            $request,
            PublicKeyCredentialUserEntity::create('john.doe', 'user-handle', 'John Doe')
        );
    }

    private static function assertCriteria(
        PublicKeyCredentialCreationOptions $options,
        ?string $expectedAuthenticatorAttachment,
        string $expectedUserVerification,
        ?string $expectedResidentKey,
    ): void {
        $criteria = $options->authenticatorSelection;
        static::assertNotNull($criteria);
        static::assertSame($expectedAuthenticatorAttachment, $criteria->authenticatorAttachment);
        static::assertSame($expectedUserVerification, $criteria->userVerification);
        static::assertSame($expectedResidentKey, $criteria->residentKey);
        static::assertSame(
            $expectedResidentKey === AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED ? true : null,
            $criteria->requireResidentKey
        );
    }

    private static function factory(
        ?string $authenticatorAttachment,
        ?string $residentKey,
    ): PublicKeyCredentialCreationOptionsFactory {
        return new PublicKeyCredentialCreationOptionsFactory([
            'strict' => [
                'rp' => [
                    'name' => 'Example',
                    'id' => 'example.com',
                ],
                'challenge_length' => 32,
                'authenticator_selection_criteria' => [
                    'authenticator_attachment' => $authenticatorAttachment,
                    'user_verification' => AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                    'resident_key' => $residentKey,
                ],
                'public_key_credential_parameters' => [-7],
                'extensions' => [],
            ],
        ]);
    }

    private static function defaultPolicy(): ClientOverridePolicy
    {
        $config = (new Processor())->processConfiguration(new Configuration('webauthn'), []);

        return new ClientOverridePolicy($config['client_override_policy']);
    }
}
