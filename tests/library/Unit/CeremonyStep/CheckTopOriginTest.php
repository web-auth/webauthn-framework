<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\CeremonyStep;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CheckTopOrigin;
use Webauthn\CeremonyStep\TopOriginValidator;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Issue #900: a cross-origin response must not be silently accepted when no
 * TopOriginValidator is configured. The WebAuthn spec requires the RP to
 * verify topOrigin, so the step must fail closed.
 *
 * @internal
 */
final class CheckTopOriginTest extends AbstractTestCase
{
    #[Test]
    public function stepIsSkippedWhenTopOriginIsAbsent(): void
    {
        $step = new CheckTopOrigin();

        $step->process(
            $this->credentialRecord(),
            $this->assertionResponse(topOrigin: null, crossOrigin: false),
            $this->requestOptions(),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function stepThrowsWhenTopOriginIsPresentButCrossOriginIsFalse(): void
    {
        $step = new CheckTopOrigin();

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The response is not cross-origin.');

        $step->process(
            $this->credentialRecord(),
            $this->assertionResponse(topOrigin: 'https://wallet.example.com', crossOrigin: false),
            $this->requestOptions(),
            null,
            'example.com',
        );
    }

    #[Test]
    public function stepThrowsWhenTopOriginIsPresentAndNoValidatorIsConfigured(): void
    {
        $step = new CheckTopOrigin();

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('no TopOriginValidator is configured');

        $step->process(
            $this->credentialRecord(),
            $this->assertionResponse(topOrigin: 'https://wallet.example.com', crossOrigin: true),
            $this->requestOptions(),
            null,
            'example.com',
        );
    }

    #[Test]
    public function stepDelegatesToTheConfiguredValidatorWhenCrossOriginIsLegitimate(): void
    {
        $received = null;
        $step = new CheckTopOrigin(new class($received) implements TopOriginValidator {
            public function __construct(
                private mixed &$captured
            ) {
            }

            public function validate(string $topOrigin): void
            {
                $this->captured = $topOrigin;
            }
        });

        $step->process(
            $this->credentialRecord(),
            $this->assertionResponse(topOrigin: 'https://wallet.example.com', crossOrigin: true),
            $this->requestOptions(),
            null,
            'example.com',
        );

        static::assertSame('https://wallet.example.com', $received);
    }

    #[Test]
    public function stepPropagatesRejectionFromTheConfiguredValidator(): void
    {
        $step = new CheckTopOrigin(new class() implements TopOriginValidator {
            public function validate(string $topOrigin): void
            {
                throw AuthenticatorResponseVerificationException::create('rejected by validator');
            }
        });

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('rejected by validator');

        $step->process(
            $this->credentialRecord(),
            $this->assertionResponse(topOrigin: 'https://attacker.example.com', crossOrigin: true),
            $this->requestOptions(),
            null,
            'example.com',
        );
    }

    private function credentialRecord(): CredentialRecord
    {
        return CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            0,
        );
    }

    private function requestOptions(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create('challenge-bytes');
    }

    private function assertionResponse(?string $topOrigin, bool $crossOrigin): AuthenticatorAssertionResponse
    {
        $clientData = [
            'type' => 'webauthn.get',
            'challenge' => 'challenge-bytes',
            'origin' => 'https://example.com',
            'crossOrigin' => $crossOrigin,
        ];
        if ($topOrigin !== null) {
            $clientData['topOrigin'] = $topOrigin;
        }

        $authData = AuthenticatorData::create(
            authData: '',
            rpIdHash: str_repeat("\0", 32),
            flags: "\0",
            signCount: 0,
        );

        return AuthenticatorAssertionResponse::create(
            CollectedClientData::create('{}', $clientData),
            $authData,
            'signature',
        );
    }
}
