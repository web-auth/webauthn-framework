<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;
use const JSON_THROW_ON_ERROR;

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
        static::assertSame(
            '{"rp":{"name":"RP"},"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"attestation":"direct"}',
            json_encode($options, JSON_THROW_ON_ERROR)
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
        static::assertSame(
            '{"rp":{"name":"RP"},"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"attestation":"direct"}',
            json_encode($data, JSON_THROW_ON_ERROR)
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

        $json = json_encode($options, JSON_THROW_ON_ERROR);
        static::assertSame(
            // '{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"indirect","user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"authenticatorSelection":{"userVerification":"preferred","residentKey":"preferred"},"excludeCredentials":[],"timeout":1000}', // TODO: On hold. Waiting for issue clarification. See https://github.com/fido-alliance/conformance-test-tools-resources/issues/676
            '{"rp":{"name":"RP"},"user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"type","alg":-100}],"timeout":1000,"attestation":"indirect"}',
            $json
        );

        $data = $this->getSerializer()
            ->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json');
        static::assertSame([], $data->excludeCredentials);
    }
}
