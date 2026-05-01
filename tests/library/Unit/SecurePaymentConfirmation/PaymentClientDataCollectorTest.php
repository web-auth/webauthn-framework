<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\PaymentExtension;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\ClientDataCollector\PaymentClientDataCollector;
use Webauthn\CollectedClientData;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class PaymentClientDataCollectorTest extends AbstractTestCase
{
    #[Test]
    public function supportsOnlyPaymentGet(): void
    {
        $collector = new PaymentClientDataCollector($this->getSerializer());
        static::assertSame(['payment.get'], $collector->supportedTypes());
    }

    #[Test]
    public function rejectsCreationCeremony(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('"payment.get" client data type can only appear in an assertion');

        $this->collector()
            ->verifyCollectedClientData(
                $this->paymentClientData(),
                PublicKeyCredentialCreationOptions::create(
                    PublicKeyCredentialRpEntity::create(),
                    PublicKeyCredentialUserEntity::create('u', 'h', 'User'),
                    'challenge',
                ),
                $this->fakeAssertionResponse(),
                'example.com',
            );
    }

    #[Test]
    public function rejectsRequestWithoutPaymentExtension(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('must include a "payment" extension');

        $this->collector()
            ->verifyCollectedClientData(
                $this->paymentClientData(),
                PublicKeyCredentialRequestOptions::create('challenge'),
                $this->fakeAssertionResponse(),
                'example.com',
            );
    }

    #[Test]
    public function rejectsClientDataWithoutPaymentField(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Missing "payment" field');

        $rawData = json_encode([
            'type' => 'payment.get',
            'challenge' => $this->b64('challenge'),
            'origin' => 'https://example.com',
        ], JSON_THROW_ON_ERROR);
        $clientData = CollectedClientData::create($rawData, json_decode($rawData, true));

        $this->collector()
            ->verifyCollectedClientData(
                $clientData,
                $this->requestOptionsWithPayment(),
                $this->fakeAssertionResponse(),
                'example.com',
            );
    }

    #[Test]
    public function acceptsMatchingInputAndSignedPayment(): void
    {
        $this->collector()
            ->verifyCollectedClientData(
                $this->paymentClientData(),
                $this->requestOptionsWithPayment(),
                $this->fakeAssertionResponse(),
                'example.com',
            );
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function detectsAmountTampering(): void
    {
        // The signed payload says $9999.00 even though the merchant requested $99.99 — the attack SPC is built to defeat.
        $tampered = $this->paymentClientData([
            'total' => [
                'currency' => 'USD',
                'value' => '9999.00',
            ],
        ]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Payment total.value mismatch');

        $this->collector()
            ->verifyCollectedClientData(
                $tampered,
                $this->requestOptionsWithPayment(),
                $this->fakeAssertionResponse(),
                'example.com',
            );
    }

    #[Test]
    public function detectsRpIdTampering(): void
    {
        $tampered = $this->paymentClientData([
            'rpId' => 'evil.com',
        ]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Payment rpId mismatch');

        $this->collector()
            ->verifyCollectedClientData(
                $tampered,
                $this->requestOptionsWithPayment(),
                $this->fakeAssertionResponse(),
                'example.com',
            );
    }

    #[Test]
    public function detectsInstrumentTampering(): void
    {
        $tampered = $this->paymentClientData([
            'instrument' => [
                'displayName' => 'Attacker Card',
                'icon' => 'https://example.com/visa-icon.png',
            ],
        ]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Payment instrument.displayName mismatch');

        $this->collector()
            ->verifyCollectedClientData(
                $tampered,
                $this->requestOptionsWithPayment(),
                $this->fakeAssertionResponse(),
                'example.com',
            );
    }

    private function collector(): PaymentClientDataCollector
    {
        return new PaymentClientDataCollector($this->getSerializer());
    }

    private function requestOptionsWithPayment(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(
            'challenge',
            extensions: new AuthenticationExtensions([
                PaymentExtension::authenticate(
                    rpId: 'example.com',
                    topOrigin: 'https://merchant.example.com',
                    total: PaymentCurrencyAmount::create('USD', '99.99'),
                    instrument: PaymentCredentialInstrument::create(
                        'Visa •••• 1234',
                        'https://example.com/visa-icon.png',
                    ),
                    payeeName: 'Merchant Store',
                    payeeOrigin: 'https://merchant.example.com',
                ),
            ]),
        );
    }

    /**
     * @param array<string, mixed> $paymentOverrides
     */
    private function paymentClientData(array $paymentOverrides = []): CollectedClientData
    {
        $payment = array_merge([
            'rpId' => 'example.com',
            'topOrigin' => 'https://merchant.example.com',
            'total' => [
                'currency' => 'USD',
                'value' => '99.99',
            ],
            'instrument' => [
                'displayName' => 'Visa •••• 1234',
                'icon' => 'https://example.com/visa-icon.png',
            ],
            'payeeName' => 'Merchant Store',
            'payeeOrigin' => 'https://merchant.example.com',
        ], $paymentOverrides);

        $rawData = json_encode([
            'type' => 'payment.get',
            'challenge' => $this->b64('challenge'),
            'origin' => 'https://example.com',
            'payment' => $payment,
        ], JSON_THROW_ON_ERROR);

        return CollectedClientData::create($rawData, json_decode($rawData, true));
    }

    private function fakeAssertionResponse(): AuthenticatorAssertionResponse
    {
        // The collector does not consult the assertion response itself — it
        // only inspects clientDataJSON.payment + the request options. A bare
        // mock keeps these tests focused on the collector's contract.
        return static::createStub(AuthenticatorAssertionResponse::class);
    }

    private function b64(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
