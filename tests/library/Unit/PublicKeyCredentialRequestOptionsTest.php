<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\AbstractTestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class PublicKeyCredentialRequestOptionsTest extends AbstractTestCase
{
    #[Test]
    public function authenticatorExtensionSerialization(): void
    {
        // Given
        $extensions = AuthenticationExtensions::create([AuthenticationExtension::create('foo', 'bar')]);
        $extensions['baz'] = 'New era';
        $json = json_encode($extensions, JSON_THROW_ON_ERROR);

        // When
        $data = $this->getSerializer()
            ->deserialize($json, AuthenticationExtensions::class, 'json');

        // Then
        static::assertSame('{"foo":"bar","baz":"New era"}', $json);
        static::assertSame('bar', $data->get('foo')->value);
        static::assertSame('bar', $data['foo']->value);
        static::assertSame('New era', $data['baz']->value);
        static::assertSame($json, json_encode($data, JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function aPublicKeyCredentialRequestOptionsCanBeCreatedAndValueAccessed(): void
    {
        $extensions = AuthenticationExtensions::create([AuthenticationExtension::create('foo', 'bar')]);
        $credential = PublicKeyCredentialDescriptor::create('type', 'id', ['transport']);

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            'challenge',
            rpId: 'rp_id',
            allowCredentials: [$credential],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 1000,
            extensions: $extensions
        );

        static::assertSame('challenge', $publicKeyCredentialRequestOptions->challenge);
        static::assertSame(1000, $publicKeyCredentialRequestOptions->timeout);
        static::assertSame('rp_id', $publicKeyCredentialRequestOptions->rpId);
        static::assertSame([$credential], $publicKeyCredentialRequestOptions->allowCredentials);
        static::assertSame('preferred', $publicKeyCredentialRequestOptions->userVerification);
        static::assertInstanceOf(AuthenticationExtensions::class, $publicKeyCredentialRequestOptions->extensions);
        static::assertSame(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            json_encode($publicKeyCredentialRequestOptions, JSON_THROW_ON_ERROR)
        );

        $data = $this->getSerializer()
            ->deserialize(
                '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
                PublicKeyCredentialRequestOptions::class,
                'json'
            );
        static::assertSame('challenge', $data->challenge);
        static::assertSame(1000, $data->timeout);
        static::assertSame('rp_id', $data->rpId);
        static::assertSame('preferred', $data->userVerification);
        static::assertInstanceOf(AuthenticationExtensions::class, $data->extensions);
        static::assertSame(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }
}
