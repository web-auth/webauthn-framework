<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @internal
 */
final class PublicKeyCredentialCreationOptionsTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialCreationOptionsCanBeCreatedAndValueAccessed(): void
    {
        $rp = new PublicKeyCredentialRpEntity('RP');
        $user = new PublicKeyCredentialUserEntity('USER', 'id', 'FOO BAR');

        $credential = new PublicKeyCredentialDescriptor('type', 'id', ['transport']);
        $credentialParameters = new PublicKeyCredentialParameters('type', -100);

        $options = PublicKeyCredentialCreationOptions
            ::create($rp, $user, 'challenge', [$credentialParameters])
                ->excludeCredential($credential)
                ->setTimeout(1000)
                ->setAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT)
        ;

        static::assertSame('challenge', $options->getChallenge());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $options->getExtensions());
        static::assertSame([$credential], $options->getExcludeCredentials());
        static::assertSame([$credentialParameters], $options->getPubKeyCredParams());
        static::assertSame('direct', $options->getAttestation());
        static::assertSame(1000, $options->getTimeout());
        static::assertInstanceOf(PublicKeyCredentialRpEntity::class, $options->getRp());
        static::assertInstanceOf(PublicKeyCredentialUserEntity::class, $options->getUser());
        static::assertInstanceOf(AuthenticatorSelectionCriteria::class, $options->getAuthenticatorSelection());
        static::assertSame(
            '{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"direct","user":{"name":"USER","id":"aWQ=","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"timeout":1000}',
            json_encode($options)
        );

        $data = PublicKeyCredentialCreationOptions::createFromString(
            '{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"direct","user":{"name":"USER","id":"aWQ","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"timeout":1000}'
        );
        static::assertSame('challenge', $data->getChallenge());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $data->getExtensions());
        static::assertSame([$credential], $data->getExcludeCredentials());
        static::assertSame([$credentialParameters], $data->getPubKeyCredParams());
        static::assertSame('direct', $data->getAttestation());
        static::assertSame(1000, $data->getTimeout());
        static::assertInstanceOf(PublicKeyCredentialRpEntity::class, $data->getRp());
        static::assertInstanceOf(PublicKeyCredentialUserEntity::class, $data->getUser());
        static::assertInstanceOf(AuthenticatorSelectionCriteria::class, $data->getAuthenticatorSelection());
        static::assertSame(
            '{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"direct","user":{"name":"USER","id":"aWQ=","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"excludeCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"timeout":1000}',
            json_encode($data)
        );
    }

    /**
     * @test
     */
    public function anPublicKeyCredentialCreationOptionsWithoutExcludeCredentialsCanBeSerializedAndDeserialized(): void
    {
        $rp = new PublicKeyCredentialRpEntity('RP');
        $user = new PublicKeyCredentialUserEntity('USER', 'id', 'FOO BAR');

        $credentialParameters = new PublicKeyCredentialParameters('type', -100);

        $options = PublicKeyCredentialCreationOptions
            ::create($rp, $user, 'challenge', [$credentialParameters])
                ->setTimeout(1000)
                ->setAttestation(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT)
        ;

        $json = json_encode($options);
        static::assertSame(
            '{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"indirect","user":{"name":"USER","id":"aWQ=","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":1000}',
            $json
        );
        $data = PublicKeyCredentialCreationOptions::createFromString($json);
        static::assertSame([], $data->getExcludeCredentials());
    }
}
