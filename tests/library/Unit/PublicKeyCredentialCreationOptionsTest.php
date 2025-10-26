<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class PublicKeyCredentialCreationOptionsTest extends AbstractTestCase
{
    #[Test]
    public function anPublicKeyCredentialCreationOptionsCanBeCreatedAndValueAccessed(): void
    {
        $rp = PublicKeyCredentialRpEntity::create();
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');

        $credential = PublicKeyCredentialDescriptor::create('type', 'id', ['transport']);
        $credentialParameters = PublicKeyCredentialParameters::create('type', -100);

        $options = PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            'challenge',
            [$credentialParameters],
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            excludeCredentials: [$credential],
            timeout: 1000
        );

        static::assertSame('challenge', $options->challenge);
        static::assertSame([$credential], $options->excludeCredentials);
        static::assertSame([$credentialParameters], $options->pubKeyCredParams);
        static::assertSame('direct', $options->attestation);
        static::assertSame(1000, $options->timeout);
        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"attestation":"direct"}',
            $this->getSerializer()
                ->serialize($options, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );

        $data = $this->getSerializer()
            ->deserialize(
                '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"attestation":"direct"}',
                PublicKeyCredentialCreationOptions::class,
                'json'
            );
        static::assertSame('challenge', $data->challenge);
        static::assertSame('direct', $data->attestation);
        static::assertSame(1000, $data->timeout);
        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"attestation":"direct"}',
            $this->getSerializer()
                ->serialize($data, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );
    }

    #[Test]
    public function anPublicKeyCredentialCreationOptionsWithoutExcludeCredentialsCanBeSerializedAndDeserialized(): void
    {
        $rp = PublicKeyCredentialRpEntity::create();
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');

        $credentialParameters = PublicKeyCredentialParameters::create('type', -100);

        $options = PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            'challenge',
            [$credentialParameters],
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
            timeout: 1000
        );

        $json = $this->getSerializer()
            ->serialize($options, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);
        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"excludeCredentials": [],"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"attestation":"indirect"}',
            $json
        );

        $data = $this->getSerializer()
            ->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);
        static::assertSame([], $data->excludeCredentials);
    }

    #[Test]
    public function anPublicKeyCredentialCreationOptionsWithHintsCanBeCreatedAndSerialized(): void
    {
        $rp = PublicKeyCredentialRpEntity::create();
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');
        $credentialParameters = PublicKeyCredentialParameters::create('type', -100);

        $options = PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            'challenge',
            [$credentialParameters],
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            timeout: 1000,
            hints: [
                PublicKeyCredentialCreationOptions::HINT_SECURITY_KEY,
                PublicKeyCredentialCreationOptions::HINT_HYBRID,
            ]
        );

        static::assertSame([
            PublicKeyCredentialCreationOptions::HINT_SECURITY_KEY,
            PublicKeyCredentialCreationOptions::HINT_HYBRID,
        ], $options->hints);

        $json = $this->getSerializer()
            ->serialize($options, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);
        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"excludeCredentials":[],"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"attestation":"none","hints":["security-key","hybrid"]}',
            $json
        );

        $data = $this->getSerializer()
            ->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json');
        static::assertSame(['security-key', 'hybrid'], $data->hints);
    }

    #[Test]
    public function anPublicKeyCredentialCreationOptionsWithInvalidHintThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid hint "invalid-hint". Allowed values are: security-key, client-device, hybrid'
        );

        $rp = PublicKeyCredentialRpEntity::create();
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');
        $credentialParameters = PublicKeyCredentialParameters::create('type', -100);

        PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            'challenge',
            [$credentialParameters],
            hints: ['invalid-hint']
        );
    }

    #[Test]
    public function anPublicKeyCredentialCreationOptionsWithEmptyHintsCanBeCreated(): void
    {
        $rp = PublicKeyCredentialRpEntity::create();
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');
        $credentialParameters = PublicKeyCredentialParameters::create('type', -100);

        $options = PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            'challenge',
            [$credentialParameters],
            hints: []
        );

        static::assertSame([], $options->hints);
    }
}
