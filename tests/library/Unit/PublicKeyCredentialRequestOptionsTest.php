<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\PublicKeyCredentialRequestOptions
 *
 * @internal
 */
class PublicKeyCredentialRequestOptionsTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialRequestOptionsCanBeCreatedAndValueAccessed(): void
    {
        $extensions = AuthenticationExtensionsClientInputs::create();
        $extensions->add(AuthenticationExtension::create('foo', 'bar'));

        $credential = PublicKeyCredentialDescriptor::create('type', 'id', ['transport']);

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
            ::create('challenge')
                ->setTimeout(1000)
                ->setRpId('rp_id')
                ->setUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
                ->allowCredential($credential)
                ->setExtensions($extensions)
        ;

        static::assertEquals('challenge', $publicKeyCredentialRequestOptions->getChallenge());
        static::assertEquals(1000, $publicKeyCredentialRequestOptions->getTimeout());
        static::assertEquals('rp_id', $publicKeyCredentialRequestOptions->getRpId());
        static::assertEquals([$credential], $publicKeyCredentialRequestOptions->getAllowCredentials());
        static::assertEquals('preferred', $publicKeyCredentialRequestOptions->getUserVerification());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $publicKeyCredentialRequestOptions->getExtensions());
        static::assertEquals('{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}', json_encode($publicKeyCredentialRequestOptions));

        $data = PublicKeyCredentialRequestOptions::createFromString('{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}');
        static::assertEquals('challenge', $data->getChallenge());
        static::assertEquals(1000, $data->getTimeout());
        static::assertEquals('rp_id', $data->getRpId());
        static::assertEquals([$credential], $data->getAllowCredentials());
        static::assertEquals('preferred', $data->getUserVerification());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $data->getExtensions());
        static::assertEquals('{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"preferred","allowCredentials":[{"type":"type","id":"aWQ","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}', json_encode($data));
    }
}
