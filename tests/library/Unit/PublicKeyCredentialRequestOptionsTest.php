<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\AbstractTestCase;

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
        $json = $this->getSerializer()
            ->serialize($extensions, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // When
        $data = $this->getSerializer()
            ->deserialize($json, AuthenticationExtensions::class, 'json');

        // Then
        static::assertSame('{"foo":"bar","baz":"New era"}', $json);
        static::assertSame('bar', $data->get('foo')->value);
        static::assertSame('bar', $data['foo']->value);
        static::assertSame('New era', $data['baz']->value);
        static::assertSame($json, $this->getSerializer()->serialize($data, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
    }

    #[Test]
    public function aPublicKeyCredentialRequestOptionsCanBeCreatedAndValueAccessed(): void
    {
        $extensions = AuthenticationExtensionsClientInputs::create([AuthenticationExtension::create('foo', 'bar')]);
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
        static::assertJsonStringEqualsJsonString(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            $this->getSerializer()
                ->serialize($publicKeyCredentialRequestOptions, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
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
        static::assertJsonStringEqualsJsonString(
            '{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}',
            $this->getSerializer()
                ->serialize($data, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );
    }
}
