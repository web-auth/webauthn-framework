<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedCreationOptionsBuilder;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedRequestOptionsBuilder;
use Webauthn\Bundle\DependencyInjection\Configuration;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Under the bundle's default client override policy, the client may add extensions to the options of a profile but
 * never remove nor replace the extensions the profile sets. An extension the ceremony relies on, such as the Secure
 * Payment Confirmation `payment` input, therefore always reaches the stored options.
 *
 * @internal
 */
final class ClientExtensionsOverrideTest extends KernelTestCase
{
    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function creationRequests(): iterable
    {
        yield 'no extensions member' => [
            '{}',
            [
                'payment' => [
                    'isPayment' => true,
                ],
                'credProps' => true,
            ],
        ];
        yield 'empty extensions' => [
            '{"extensions": {}}',
            [
                'payment' => [
                    'isPayment' => true,
                ],
                'credProps' => true,
            ],
        ];
        yield 'an extension of the profile replaced' => [
            '{"extensions": {"credProps": false, "payment": {"isPayment": false}}}',
            [
                'payment' => [
                    'isPayment' => true,
                ],
                'credProps' => true,
            ],
        ];
        yield 'another extension added' => [
            '{"extensions": {"uvm": true}}',
            [
                'payment' => [
                    'isPayment' => true,
                ],
                'credProps' => true,
                'uvm' => true,
            ],
        ];
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function requestRequests(): iterable
    {
        yield 'empty extensions' => [
            '{"extensions": {}}',
            [
                'payment' => self::paymentInput('10.00'),
            ],
        ];
        yield 'the payment input replaced' => [
            '{"extensions": {"payment": {"isPayment": true, "total": {"currency": "EUR", "value": "0.01"}}}}',
            [
                'payment' => self::paymentInput('10.00'),
            ],
        ];
        yield 'another extension added' => [
            '{"extensions": {"uvm": true}}',
            [
                'payment' => self::paymentInput('10.00'),
                'uvm' => true,
            ],
        ];
    }

    /**
     * @param array<string, mixed> $expectedExtensions
     */
    #[Test]
    #[DataProvider('creationRequests')]
    public function theCreationOptionsKeepTheExtensionsOfTheProfile(string $body, array $expectedExtensions): void
    {
        $credentialRecordRepository = self::bootedContainer()->get(PublicKeyCredentialSourceRepository::class);
        static::assertInstanceOf(PublicKeyCredentialSourceRepository::class, $credentialRecordRepository);
        $builder = new ProfileBasedCreationOptionsBuilder(
            self::serializer(),
            self::validator(),
            $credentialRecordRepository,
            new PublicKeyCredentialCreationOptionsFactory([
                'profile' => [
                    'rp' => [
                        'name' => 'Example',
                        'id' => 'example.com',
                    ],
                    'challenge_length' => 32,
                    'authenticator_selection_criteria' => [
                        'authenticator_attachment' => null,
                        'user_verification' => 'required',
                        'resident_key' => 'required',
                    ],
                    'public_key_credential_parameters' => [-7],
                    'extensions' => [
                        'payment' => [
                            'isPayment' => true,
                        ],
                        'credProps' => true,
                    ],
                ],
            ]),
            'profile',
            self::defaultPolicy()
        );

        $options = $builder->getFromRequest(
            self::jsonRequest($body),
            PublicKeyCredentialUserEntity::create('john.doe', 'user-handle', 'John Doe')
        );

        self::assertExtensions($expectedExtensions, $options->extensions);
    }

    /**
     * @param array<string, mixed> $expectedExtensions
     */
    #[Test]
    #[DataProvider('requestRequests')]
    public function theRequestOptionsKeepTheExtensionsOfTheProfile(string $body, array $expectedExtensions): void
    {
        $container = self::bootedContainer();
        $userEntityRepository = $container->get(PublicKeyCredentialUserEntityRepository::class);
        static::assertInstanceOf(PublicKeyCredentialUserEntityRepository::class, $userEntityRepository);
        $credentialRecordRepository = $container->get(PublicKeyCredentialSourceRepository::class);
        static::assertInstanceOf(PublicKeyCredentialSourceRepository::class, $credentialRecordRepository);
        $builder = new ProfileBasedRequestOptionsBuilder(
            self::serializer(),
            self::validator(),
            $userEntityRepository,
            $credentialRecordRepository,
            new PublicKeyCredentialRequestOptionsFactory([
                'profile' => [
                    'challenge_length' => 32,
                    'rp_id' => 'example.com',
                    'extensions' => [
                        'payment' => self::paymentInput('10.00'),
                    ],
                ],
            ]),
            'profile',
            null,
            self::defaultPolicy()
        );

        $options = $builder->getFromRequest(self::jsonRequest($body));

        self::assertExtensions($expectedExtensions, $options->extensions);
    }

    #[Test]
    public function theExtensionsOfAnUnknownRequestProfileCannotBeRead(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The profile with key "unknown" does not exist.');

        (new PublicKeyCredentialRequestOptionsFactory([]))->getExtensions('unknown');
    }

    /**
     * @return array<string, mixed>
     */
    private static function paymentInput(string $amount): array
    {
        return [
            'isPayment' => true,
            'rpId' => 'example.com',
            'topOrigin' => 'https://merchant.example.com',
            'total' => [
                'currency' => 'EUR',
                'value' => $amount,
            ],
            'instrument' => [
                'displayName' => 'Card',
                'icon' => 'https://example.com/card.png',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $expected
     */
    private static function assertExtensions(array $expected, AuthenticationExtensions $extensions): void
    {
        $actual = [];
        foreach ($extensions->extensions as $name => $extension) {
            $actual[$name] = $extension->value;
        }
        ksort($expected);
        ksort($actual);

        static::assertSame($expected, $actual);
    }

    private static function bootedContainer(): ContainerInterface
    {
        self::bootKernel();

        return self::getContainer();
    }

    private static function serializer(): SerializerInterface
    {
        $serializer = self::getContainer()->get('serializer');
        static::assertInstanceOf(SerializerInterface::class, $serializer);

        return $serializer;
    }

    private static function validator(): ValidatorInterface
    {
        $validator = self::getContainer()->get('validator');
        static::assertInstanceOf(ValidatorInterface::class, $validator);

        return $validator;
    }

    private static function jsonRequest(string $body): Request
    {
        $request = Request::create('/options', Request::METHOD_POST, [], [], [], [], $body);
        $request->headers->set('Content-Type', 'application/json');

        return $request;
    }

    private static function defaultPolicy(): ClientOverridePolicy
    {
        $config = (new Processor())->processConfiguration(new Configuration('webauthn'), []);

        return new ClientOverridePolicy($config['client_override_policy']);
    }
}
