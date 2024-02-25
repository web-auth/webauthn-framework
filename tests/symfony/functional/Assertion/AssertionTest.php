<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Assertion;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\MockedRequestTrait;

/**
 * @internal
 */
final class AssertionTest extends WebTestCase
{
    use MockedRequestTrait;

    #[Test]
    public function anAssertionResponseCanBeLoadedAndVerified(): void
    {
        $publicKeyCredential = null;
        $descriptor = null;
        $response = null;
        $publicKeyCredentialRequestOptions = null;
        self::bootKernel();
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true)
        );
        $publicKeyCredentialRequestOptions->timeout = 60000;
        $publicKeyCredentialRequestOptions->rpId = 'localhost';
        $publicKeyCredentialRequestOptions->userVerification = PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $publicKeyCredentialRequestOptions->allowCredentials = [
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64UrlSafe::decode(
                    'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w'
                )
            ),
        ];
        /** @var SerializerInterface $serializer */
        $serializer = self::getContainer()->get(SerializerInterface::class);
        $publicKeyCredential = $serializer->deserialize(
            '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}',
            PublicKeyCredential::class,
            'json'
        );
        $publicKeyCredentialSource = self::getContainer()->get(
            PublicKeyCredentialSourceRepositoryInterface::class
        )->findOneByCredentialId($publicKeyCredential->rawId);
        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->type);
        static::assertSame(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            $descriptor->id
        );
        static::assertSame([], $descriptor->transports);
        $response = $publicKeyCredential->response;
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);
        static::assertNull($response->userHandle);
        self::getContainer()->get(AuthenticatorAssertionResponseValidator::class)->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );
    }

    #[Test]
    public function aPublicKeyCredentialCreationOptionsCanBeCreatedFromProfile(): void
    {
        self::bootKernel();
        $allowedCredentials = [
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64UrlSafe::decode(
                    'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w'
                )
            ),
        ];
        /** @var PublicKeyCredentialRequestOptionsFactory $factory */
        $factory = self::getContainer()->get(PublicKeyCredentialRequestOptionsFactory::class);
        $options = $factory->create('default', $allowedCredentials);
        static::assertNull($options->timeout);
        static::assertSame('localhost', $options->rpId);
        static::assertSame($allowedCredentials, $options->allowCredentials);
        static::assertSame('preferred', $options->userVerification);
        static::assertInstanceOf(AuthenticationExtensions::class, $options->extensions);
    }
}
