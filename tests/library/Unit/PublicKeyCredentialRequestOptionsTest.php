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

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create('challenge');
        $publicKeyCredentialRequestOptions->timeout = 1000;
        $publicKeyCredentialRequestOptions->rpId = 'rp_id';
        $publicKeyCredentialRequestOptions->userVerification = PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $publicKeyCredentialRequestOptions->allowCredentials = [$credential];
        $publicKeyCredentialRequestOptions->extensions = $extensions;

        static::assertSame('challenge', $publicKeyCredentialRequestOptions->challenge);
        static::assertSame(1000, $publicKeyCredentialRequestOptions->timeout);
        static::assertSame('rp_id', $publicKeyCredentialRequestOptions->rpId);
        static::assertSame([$credential], $publicKeyCredentialRequestOptions->allowCredentials);
        static::assertSame('preferred', $publicKeyCredentialRequestOptions->userVerification);
        static::assertInstanceOf(
            AuthenticationExtensionsClientInputs::class,
            $publicKeyCredentialRequestOptions->extensions
        );
        static::assertSame(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            json_encode($publicKeyCredentialRequestOptions, JSON_THROW_ON_ERROR)
        );

        $data = PublicKeyCredentialRequestOptions::createFromString(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}'
        );
        static::assertSame('challenge', $data->challenge);
        static::assertSame(1000, $data->timeout);
        static::assertSame('rp_id', $data->rpId);
        static::assertSame('preferred', $data->userVerification);
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $data->extensions);
        static::assertSame(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }
}
