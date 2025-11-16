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
    public function serializingAndDeserializingOptionsWithExcludeCredentialsPreservesAllValues(): void
    {
        // Given
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

        // When
        $serialized = $this->getSerializer()
            ->serialize($options, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        $deserialized = $this->getSerializer()
            ->deserialize(
                '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"attestation":"direct"}',
                PublicKeyCredentialCreationOptions::class,
                'json'
            );

        // Then
        static::assertSame('challenge', $options->challenge);
        static::assertSame([$credential], $options->excludeCredentials);
        static::assertSame([$credentialParameters], $options->pubKeyCredParams);
        static::assertSame('direct', $options->attestation);
        static::assertSame(1000, $options->timeout);
        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"attestation":"direct"}',
            $serialized
        );

        static::assertSame('challenge', $deserialized->challenge);
        static::assertSame('direct', $deserialized->attestation);
        static::assertSame(1000, $deserialized->timeout);
        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"attestation":"direct"}',
            $this->getSerializer()
                ->serialize($deserialized, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );
    }

    #[Test]
    public function serializingOptionsWithoutExcludeCredentialsPreservesEmptyArray(): void
    {
        // Given
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

        // When
        $json = $this->getSerializer()
            ->serialize($options, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        $deserialized = $this->getSerializer()
            ->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"excludeCredentials": [],"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"attestation":"indirect"}',
            $json
        );
        static::assertSame([], $deserialized->excludeCredentials);
    }

    #[Test]
    public function serializingOptionsWithHintsIncludesHintsInJson(): void
    {
        // Given
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

        // When
        $json = $this->getSerializer()
            ->serialize($options, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        $deserialized = $this->getSerializer()
            ->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json');

        // Then
        static::assertSame([
            PublicKeyCredentialCreationOptions::HINT_SECURITY_KEY,
            PublicKeyCredentialCreationOptions::HINT_HYBRID,
        ], $options->hints);

        static::assertJsonStringEqualsJsonString(
            '{"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"excludeCredentials":[],"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"attestation":"none","hints":["security-key","hybrid"]}',
            $json
        );

        static::assertSame(['security-key', 'hybrid'], $deserialized->hints);
    }

    #[Test]
    public function creatingOptionsWithInvalidHintThrowsException(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid hint "invalid-hint". Allowed values are: security-key, client-device, hybrid'
        );

        // Given
        $rp = PublicKeyCredentialRpEntity::create();
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');
        $credentialParameters = PublicKeyCredentialParameters::create('type', -100);

        // When
        PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            'challenge',
            [$credentialParameters],
            hints: ['invalid-hint']
        );
    }

    #[Test]
    public function creatingOptionsWithEmptyHintsPreservesEmptyArray(): void
    {
        // Given
        $rp = PublicKeyCredentialRpEntity::create();
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');
        $credentialParameters = PublicKeyCredentialParameters::create('type', -100);

        // When
        $options = PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            'challenge',
            [$credentialParameters],
            hints: []
        );

        // Then
        static::assertSame([], $options->hints);
    }
}
