<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use RangeException;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AttestationTest extends AbstractTestCase
{
    #[Test]
    public function aResponseCannotBeLoaded(): void
    {
        static::expectException(RangeException::class);
        static::expectExceptionMessage('Incorrect padding');
        $response = '{"id":"wHU13DaUWRqIQq94SAfCG8jqUZGdW0N95hnchI3rG7s===","rawId":"wHU13DaUWRqIQq94SAfCG8jqUZGdW0N95hnchI3rG7s","response":{"authenticatorData":"lgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1kBAAAAag","signature":"MEYCIQD4faYQG08_xpmAxFwp33OObSPavG7iUCJimHhH2QwyVAIhAMVRovz5DR_itNGYzTpKgO2urLgx5F2mZf3U4INTRR74","userHandle":"MDFHN0VEWUMxQ1QxSjBUUVBIWEY3QVlGNUs","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IkhaaktrWURKTEgtVnF6bFgtaXpCcUc3Q1pvN0FVRmtobG12TnRHM1VKSjQiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"},"getClientExtensionResults":{},"type":"public-key"}';
        $this->getSerializer()
            ->deserialize($response, PublicKeyCredential::class, 'json');
    }

    #[Test]
    public function anAttestationSignedWithEcDSA521ShouldBeVerified(): void
    {
        $options = '{"rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-46},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"MJr5sD0WitVwZM0eoSO6kWhyseT67vc3oQdk_k1VdZQ","attestation":"direct","user":{"name":"zOEOkAZGg3ZrD8l_TFwD","id":"ZDYzNGZlZGQtMGZiNi00ZDY3LWI5OGEtNDk2OWY2ZTMwNTY1","displayName":"Shenika Olin"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $response = '{"id":"R4fAVj9osgVVZL7yHftPeVOmjom3xw4ZLK7Dt_8mzOM","rawId":"R4fAVj9osgVVZL7yHftPeVOmjom3xw4ZLK7Dt/8mzOM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzgjY3NpZ1iLMIGIAkIA-KkXe-BmfxZgJNet2JPOZ6-fjPQskjnqOYWf7LW2iMFDbbZ3_oU18m0IGVksCPOaSsDs6MC14CQSqcQpvo0YxHMCQgFKm882cBfrPs4zM7piS3bM3yG6W4OrS9bbIj34e7b9JNH0Ee-w0cAeUaxQNyyedC4y4fSqvUjDT0f0Mj-iE0-pa2hhdXRoRGF0YVjplgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1lBAAAAlSOIq42JFUFGk7rUPmcdJTgAIEeHwFY_aLIFVWS-8h37T3lTpo6Jt8cOGSyuw7f_JszjpQECAzgjIAMhWEIA6Q6fXXQzt2RH6cq4eKJpfFU4nhmCWH2DKAa33T-uGStxA0zaA3goYphgRW6PkgyETh-Q4I3-NJ6KCx-5QV39v50iWEIAA9xyNnqltQaG2UuiLtuSNM59PLv3skYKKmnAvUDT7J6YwPwVyzOWKOyIfgQc9oPO9dRQ21Da498iOhx5qA5gbRo","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6Ik1KcjVzRDBXaXRWd1pNMGVvU082a1doeXNlVDY3dmMzb1Fka19rMVZkWlEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","transports":["usb"]},"type":"public-key"}';
        $serializer = $this->getSerializer();
        $publicKeyCredentialCreationOptions = $serializer->deserialize(
            $options,
            PublicKeyCredentialCreationOptions::class,
            'json'
        );
        $publicKeyCredential = $serializer->deserialize($response, PublicKeyCredential::class, 'json');

        // When
        $publicKeyCredentialSource = $this->getAuthenticatorAttestationResponseValidator()
            ->check(
                $publicKeyCredential->response,
                $publicKeyCredentialCreationOptions,
                'webauthn.spomky-labs.com'
            );
        // Then
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);
        static::assertSame(['usb'], $publicKeyCredentialSource->transports);
        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertSame(
            hex2bin('4787c0563f68b2055564bef21dfb4f7953a68e89b7c70e192caec3b7ff26cce3'),
            $publicKeyCredential->rawId
        );
        static::assertSame(
            hex2bin('4787c0563f68b2055564bef21dfb4f7953a68e89b7c70e192caec3b7ff26cce3'),
            $publicKeyCredentialDescriptor->id
        );
        static::assertSame(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $publicKeyCredentialDescriptor->type
        );
        static::assertSame(['usb'], $publicKeyCredentialDescriptor->transports);
        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $publicKeyCredential->response
            ->attestationObject
            ->authData;
        static::assertSame(
            hex2bin('9604ea82824e98a4ada14b4462d0d73a8ec469130da91b19307459229f74a359'),
            $authenticatorData->rpIdHash
        );
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertFalse($authenticatorData->isUserVerified());
        static::assertFalse($authenticatorData->isBackupEligible());
        static::assertFalse($authenticatorData->isBackedUp());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse1());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse2());
        static::assertSame(149, $authenticatorData->signCount);
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->attestedCredentialData);
        static::assertFalse($authenticatorData->hasExtensions());
    }
}
