<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Assertion;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
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
        )->setTimeout(60000)
            ->setRpId('localhost')
            ->setUserVerification(
                PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED
            )->allowCredential(
                new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64UrlSafe::decode(
                        'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w'
                    )
                )
            );
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load(
            '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}'
        );
        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertSame(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            $descriptor->getId()
        );
        static::assertSame([], $descriptor->getTransports());
        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);
        static::assertNull($response->getUserHandle());
        self::$kernel->getContainer()->get(AuthenticatorAssertionResponseValidator::class)->check(
            $publicKeyCredential->getRawId(),
            $publicKeyCredential->getResponse(),
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
            new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64UrlSafe::decode(
                    'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w'
                )
            ),
        ];
        /** @var PublicKeyCredentialRequestOptionsFactory $factory */
        $factory = self::$kernel->getContainer()->get(PublicKeyCredentialRequestOptionsFactory::class);
        $options = $factory->create('default', $allowedCredentials);
        static::assertNull($options->getTimeout());
        static::assertSame('localhost', $options->getRpId());
        static::assertSame($allowedCredentials, $options->getAllowCredentials());
        static::assertSame('preferred', $options->getUserVerification());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $options->getExtensions());
    }
}
