<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use Cose\Algorithms;
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
        $rp = PublicKeyCredentialRpEntity::create('RP');
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
            '{"rp":{"name":"RP"},"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"attestation":"direct"}',
            $this->getSerializer()
                ->serialize($options, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );

        $data = $this->getSerializer()
            ->deserialize(
                '{"rp":{"name":"RP"},"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"attestation":"direct"}',
                PublicKeyCredentialCreationOptions::class,
                'json'
            );
        static::assertSame('challenge', $data->challenge);
        static::assertSame('direct', $data->attestation);
        static::assertSame(1000, $data->timeout);
        static::assertJsonStringEqualsJsonString(
            '{"rp":{"name":"RP"},"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"attestation":"direct"}',
            $this->getSerializer()
                ->serialize($data, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );
    }

    #[Test]
    public function anPublicKeyCredentialCreationOptionsWithoutExcludeCredentialsCanBeSerializedAndDeserialized(): void
    {
        $rp = PublicKeyCredentialRpEntity::create('RP');
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
            '{"rp":{"name":"RP"},"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"excludeCredentials": [],"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"attestation":"indirect"}',
            $json
        );

        $data = $this->getSerializer()
            ->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);
        static::assertSame([], $data->excludeCredentials);
    }

    #[Test]
    public function aPublicKeyCredentialCreationOptionsIsCreatedWithDefaultAlgorithms(): void
    {
        $rp = PublicKeyCredentialRpEntity::create('RP');
        $user = PublicKeyCredentialUserEntity::create('USER', 'id', 'FOO BAR');

        $options = PublicKeyCredentialCreationOptions::create($rp, $user, 'challenge');

        $actualAlgorithms = [];
        foreach ($options->pubKeyCredParams as $pubKeyCredParam) {
            $actualAlgorithms[] = $pubKeyCredParam->alg;
        }

        static::assertSame([
            Algorithms::COSE_ALGORITHM_EDDSA,
            Algorithms::COSE_ALGORITHM_ES256,
            Algorithms::COSE_ALGORITHM_RS256,
        ], $actualAlgorithms);
    }
}
