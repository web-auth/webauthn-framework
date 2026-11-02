<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\AbstractTestCase;

/**
 * Issue #986: each ceremony accepts the client data type of its own ceremony only, "webauthn.create" for a
 * registration and "webauthn.get" for an authentication (Webauthn Level 3, sections 7.1 and 7.2).
 *
 * The responses are those of AssertionTest::previouslyFixedKeyCanBeVerified, with the type of their client data
 * swapped for the type of the other ceremony. The registration uses the "none" attestation format: nothing signs its
 * client data, so the type is the only check left to refuse it.
 *
 * @internal
 */
final class ClientDataTypeTest extends AbstractTestCase
{
    private const HOST = 'tuleap-web.tuleap-aio-dev.docker';

    private const REGISTRATION_CLIENT_DATA = '{"challenge":"sNZel5OhIwA5vR4wdVkwiGHR6QEnNhYOqi97OHQrc2A","origin":"https://tuleap-web.tuleap-aio-dev.docker","type":"%s"}';

    private const REGISTRATION = '{"clientExtensionResults": {},"id": "31ivJEY3jmIoxWuGZ7pZjDuBW5n1PAMeG-e0drfhayCzOsuNaCG3PH43i-OebKT0jqY-bAFCEUh1JCCATSPa9N5QIUwwSlUQO9Pb5X1_yXJnY9q7GYfm3LvR4Yk6-HKj4MpBj6cbVOZyoLZQtd2lDEU7pSTcbTZBELQlODGSlbQ","rawId": "31ivJEY3jmIoxWuGZ7pZjDuBW5n1PAMeG-e0drfhayCzOsuNaCG3PH43i-OebKT0jqY-bAFCEUh1JCCATSPa9N5QIUwwSlUQO9Pb5X1_yXJnY9q7GYfm3LvR4Yk6-HKj4MpBj6cbVOZyoLZQtd2lDEU7pSTcbTZBELQlODGSlbQ","response": {"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBBxawLfvD1MyjfrwvZRZlmxIhDbnhAYq58TqWkGOOpv2oRQAAAAEvwFefgRNH6rEWu1qNuSAqAIDfWK8kRjeOYijFa4ZnulmMO4FbmfU8Ax4b57R2t-FrILM6y41oIbc8fjeL455spPSOpj5sAUIRSHUkIIBNI9r03lAhTDBKVRA709vlfX_Jcmdj2rsZh-bcu9HhiTr4cqPgykGPpxtU5nKgtlC13aUMRTulJNxtNkEQtCU4MZKVtKMBY09LUAMnIGdFZDI1NTE5IZggGC0YVhiMGPEYGxjCGD8DFBiuGMAYLhhjCRjKGKYY3xhSGBgYnhhnGKEYIQwYPBjeGG0YwRidGIcY8Rjs","clientDataJSON": "%s"},"type": "public-key"}';

    private const AUTHENTICATION_CLIENT_DATA = '{"challenge":"2MSn916xPaaOcp86sSYBVsqYzROi4Y8H7Brl_8D5Drc","origin":"https://tuleap-web.tuleap-aio-dev.docker","type":"%s"}';

    private const AUTHENTICATION = '{"id": "31ivJEY3jmIoxWuGZ7pZjDuBW5n1PAMeG-e0drfhayCzOsuNaCG3PH43i-OebKT0jqY-bAFCEUh1JCCATSPa9N5QIUwwSlUQO9Pb5X1_yXJnY9q7GYfm3LvR4Yk6-HKj4MpBj6cbVOZyoLZQtd2lDEU7pSTcbTZBELQlODGSlbQ","rawId": "31ivJEY3jmIoxWuGZ7pZjDuBW5n1PAMeG-e0drfhayCzOsuNaCG3PH43i-OebKT0jqY-bAFCEUh1JCCATSPa9N5QIUwwSlUQO9Pb5X1_yXJnY9q7GYfm3LvR4Yk6-HKj4MpBj6cbVOZyoLZQtd2lDEU7pSTcbTZBELQlODGSlbQ","response": {"authenticatorData": "FrAt-8PUzKN-vC9lFmWbEiENueEBirnxOpaQY46m_agFAAAAAg","clientDataJSON": "%s","signature": "eK5Yk9G8LjEsaEbK9Qq9Ovcx_Nf9xbRU5EURdMsiqJSQMpSCMHhcOBwfhPxx_zuPfYPxv_mRPgtPrX0vNQ3YAg"},"type": "public-key","clientExtensionResults": {}}';

    #[Test]
    public function aRegistrationWithTheClientDataTypeOfAnAuthenticationIsRejected(): void
    {
        $registration = $this->registration('webauthn.get');

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The client data type is not "webauthn.create".');

        $this->getAuthenticatorAttestationResponseValidator()
            ->check($registration, $this->creationOptions(), self::HOST);
    }

    #[Test]
    public function anAuthenticationWithTheClientDataTypeOfARegistrationIsRejected(): void
    {
        $credentialRecord = $this->getAuthenticatorAttestationResponseValidator()
            ->check($this->registration('webauthn.create'), $this->creationOptions(), self::HOST);
        $authentication = $this->authentication('webauthn.create');

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The client data type is not "webauthn.get".');

        $this->getAuthenticatorAssertionResponseValidator()
            ->check($credentialRecord, $authentication, $this->requestOptions(), self::HOST, '101');
    }

    private function creationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->getSerializer()
            ->deserialize(
                '{"rp": {"id": "tuleap-web.tuleap-aio-dev.docker"},"user": {"name": "admin","id": "MTAx","displayName": "Site Administrator"},"challenge": "sNZel5OhIwA5vR4wdVkwiGHR6QEnNhYOqi97OHQrc2A","pubKeyCredParams": [{"type": "public-key","alg": -8},{"type": "public-key","alg": -7},{"type": "public-key","alg": -257}],"attestation": "none"}',
                PublicKeyCredentialCreationOptions::class,
                'json'
            );
    }

    private function requestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->getSerializer()
            ->deserialize(
                '{"challenge": "2MSn916xPaaOcp86sSYBVsqYzROi4Y8H7Brl_8D5Drc","allowCredentials": [{"type": "public-key","id": "31ivJEY3jmIoxWuGZ7pZjDuBW5n1PAMeG-e0drfhayCzOsuNaCG3PH43i-OebKT0jqY-bAFCEUh1JCCATSPa9N5QIUwwSlUQO9Pb5X1_yXJnY9q7GYfm3LvR4Yk6-HKj4MpBj6cbVOZyoLZQtd2lDEU7pSTcbTZBELQlODGSlbQ"}]}',
                PublicKeyCredentialRequestOptions::class,
                'json'
            );
    }

    private function registration(string $clientDataType): AuthenticatorAttestationResponse
    {
        $response = $this->publicKeyCredential(
            self::REGISTRATION,
            self::REGISTRATION_CLIENT_DATA,
            $clientDataType
        )->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        return $response;
    }

    private function authentication(string $clientDataType): AuthenticatorAssertionResponse
    {
        $response = $this->publicKeyCredential(
            self::AUTHENTICATION,
            self::AUTHENTICATION_CLIENT_DATA,
            $clientDataType
        )->response;
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);

        return $response;
    }

    private function publicKeyCredential(
        string $publicKeyCredential,
        string $clientData,
        string $clientDataType
    ): PublicKeyCredential {
        return $this->getSerializer()
            ->deserialize(
                sprintf($publicKeyCredential, Base64UrlSafe::encodeUnpadded(sprintf($clientData, $clientDataType))),
                PublicKeyCredential::class,
                'json'
            );
    }
}
