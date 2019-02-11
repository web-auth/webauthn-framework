<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
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
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\PublicKeyCredentialCreationOptions
 */
class PublicKeyCredentialCreationOptionsTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialCreationOptionsCanBeCreatedAndValueAccessed(): void
    {
        $rp = $this->prophesize(PublicKeyCredentialRpEntity::class);
        $rp->jsonSerialize()->willReturn(['name' => 'RP']);
        $user = $this->prophesize(PublicKeyCredentialUserEntity::class);
        $user->jsonSerialize()->willReturn(['name' => 'USER', 'id' => 'aWQ=', 'displayName' => 'FOO BAR']);

        $credential = new PublicKeyCredentialDescriptor('type', 'id', ['transport']);
        $credentialParameters = new PublicKeyCredentialParameters('type', -100);

        $options = new PublicKeyCredentialCreationOptions(
            $rp->reveal(),
            $user->reveal(),
            'challenge',
            [$credentialParameters],
            1000,
            [$credential],
            new AuthenticatorSelectionCriteria(),
            'attestation',
            new AuthenticationExtensionsClientInputs()
        );

        static::assertEquals('challenge', $options->getChallenge());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $options->getExtensions());
        static::assertEquals([$credential], $options->getExcludeCredentials());
        static::assertEquals([$credentialParameters], $options->getPubKeyCredParams());
        static::assertEquals('attestation', $options->getAttestation());
        static::assertEquals(1000, $options->getTimeout());
        static::assertInstanceOf(PublicKeyCredentialRpEntity::class, $options->getRp());
        static::assertInstanceOf(PublicKeyCredentialUserEntity::class, $options->getUser());
        static::assertInstanceOf(AuthenticatorSelectionCriteria::class, $options->getAuthenticatorSelection());
        static::assertEquals('{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"attestation","user":{"name":"USER","id":"aWQ=","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"excludeCredentials":[{"type":"type","id":"aWQ=","transports":["transport"]}],"timeout":1000}', \Safe\json_encode($options));

        $json = \Safe\json_decode('{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"attestation","user":{"name":"USER","id":"aWQ=","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"excludeCredentials":[{"type":"type","id":"aWQ=","transports":["transport"]}],"timeout":1000}', true);
        $data = PublicKeyCredentialCreationOptions::createFromJson($json);
        static::assertEquals('challenge', $data->getChallenge());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $data->getExtensions());
        static::assertEquals([$credential], $data->getExcludeCredentials());
        static::assertEquals([$credentialParameters], $data->getPubKeyCredParams());
        static::assertEquals('attestation', $data->getAttestation());
        static::assertEquals(1000, $data->getTimeout());
        static::assertInstanceOf(PublicKeyCredentialRpEntity::class, $data->getRp());
        static::assertInstanceOf(PublicKeyCredentialUserEntity::class, $data->getUser());
        static::assertInstanceOf(AuthenticatorSelectionCriteria::class, $data->getAuthenticatorSelection());
        static::assertEquals('{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"attestation","user":{"name":"USER","id":"aWQ=","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"excludeCredentials":[{"type":"type","id":"aWQ=","transports":["transport"]}],"timeout":1000}', \Safe\json_encode($data));
    }

    /**
     * @test
     */
    public function anPublicKeyCredentialCreationOptionsWithoutExcludeCredentialsCanBeSerializedAndDeserialized(): void
    {
        $rp = $this->prophesize(PublicKeyCredentialRpEntity::class);
        $rp->jsonSerialize()->willReturn(['name' => 'RP']);
        $user = $this->prophesize(PublicKeyCredentialUserEntity::class);
        $user->jsonSerialize()->willReturn(['name' => 'USER', 'id' => 'aWQ=', 'displayName' => 'FOO BAR']);

        $credentialParameters = new PublicKeyCredentialParameters('type', -100);

        $options = new PublicKeyCredentialCreationOptions(
          $rp->reveal(),
          $user->reveal(),
          'challenge',
          [$credentialParameters],
          1000,
          [],
          new AuthenticatorSelectionCriteria(),
          'attestation',
          new AuthenticationExtensionsClientInputs()
      );

        $json = \Safe\json_encode($options);
        static::assertEquals('{"rp":{"name":"RP"},"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"attestation","user":{"name":"USER","id":"aWQ=","displayName":"FOO BAR"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":1000}', $json);
        $data = PublicKeyCredentialCreationOptions::createFromJson(\Safe\json_decode($json, true));
        static::assertEquals([], $data->getExcludeCredentials());
    }
}
