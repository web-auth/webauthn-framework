<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class PublicKeyCredentialRequestOptionsTest extends TestCase
{
    #[Test]
    public function anPublicKeyCredentialRequestOptionsCanBeCreatedAndValueAccessed(): void
    {
        $extensions = AuthenticationExtensionsClientInputs::create([AuthenticationExtension::create('foo', 'bar')]);
        $credential = PublicKeyCredentialDescriptor::create('type', 'id', ['transport']);

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
            ::create('challenge')
                ->setTimeout(1000)
                ->setRpId('rp_id')
                ->setUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
                ->allowCredential($credential)
                ->setExtensions($extensions);

        static::assertSame('challenge', $publicKeyCredentialRequestOptions->getChallenge());
        static::assertSame(1000, $publicKeyCredentialRequestOptions->getTimeout());
        static::assertSame('rp_id', $publicKeyCredentialRequestOptions->getRpId());
        static::assertSame([$credential], $publicKeyCredentialRequestOptions->getAllowCredentials());
        static::assertSame('preferred', $publicKeyCredentialRequestOptions->getUserVerification());
        static::assertInstanceOf(
            AuthenticationExtensionsClientInputs::class,
            $publicKeyCredentialRequestOptions->getExtensions()
        );
        static::assertSame(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            json_encode($publicKeyCredentialRequestOptions, JSON_THROW_ON_ERROR)
        );

        $data = PublicKeyCredentialRequestOptions::createFromString(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}'
        );
        static::assertSame('challenge', $data->getChallenge());
        static::assertSame(1000, $data->getTimeout());
        static::assertSame('rp_id', $data->getRpId());
        static::assertSame('preferred', $data->getUserVerification());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $data->getExtensions());
        static::assertSame(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }
}
