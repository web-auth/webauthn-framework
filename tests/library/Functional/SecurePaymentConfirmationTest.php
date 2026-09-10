<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticationExtensions\PaymentExtension;
use Webauthn\AuthenticationExtensions\PaymentExtensionOutputChecker;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\ClientDataCollector\PaymentClientDataCollector;
use Webauthn\CollectedClientData;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\CollectedClientPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class SecurePaymentConfirmationTest extends AbstractTestCase
{
    #[Test]
    public function paymentDataStructuresCanBeCreatedAndSerialized(): void
    {
        $additionalData = CollectedClientAdditionalPaymentData::create(
            rpId: 'example.com',
            topOrigin: 'https://merchant.example.com',
            total: PaymentCurrencyAmount::create('EUR', '150.00'),
            instrument: PaymentCredentialInstrument::create(
                'MasterCard •••• 5678',
                'https://example.com/mc-icon.png',
                false
            ),
            payeeName: 'Merchant Store',
            payeeOrigin: 'https://merchant.example.com',
        );
        $paymentData = CollectedClientPaymentData::create($additionalData);

        $serialized = $this->getSerializer()
            ->serialize($paymentData, 'json');
        $deserialized = $this->getSerializer()
            ->deserialize($serialized, CollectedClientPaymentData::class, 'json');

        static::assertEquals($paymentData, $deserialized);
        static::assertSame('example.com', $deserialized->payment->rpId);
        static::assertSame('https://merchant.example.com', $deserialized->payment->topOrigin);
        static::assertSame('EUR', $deserialized->payment->total->currency);
        static::assertFalse($deserialized->payment->instrument->iconMustBeShown);
    }

    #[Test]
    public function registerExtensionEmitsOnlyIsPaymentFlag(): void
    {
        $registration = PaymentExtension::register();

        static::assertSame('payment', $registration->name);
        static::assertSame([
            'isPayment' => true,
        ], $registration->value);
    }

    #[Test]
    public function authenticateExtensionEmitsFullPaymentPayload(): void
    {
        $authentication = PaymentExtension::authenticate(
            rpId: 'example.com',
            topOrigin: 'https://merchant.example.com',
            total: PaymentCurrencyAmount::create('USD', '99.99'),
            instrument: PaymentCredentialInstrument::create(
                'Visa •••• 1234',
                'https://example.com/visa-icon.png',
            ),
            payeeName: 'Merchant Store',
            payeeOrigin: 'https://merchant.example.com',
        );

        static::assertSame('payment', $authentication->name);
        static::assertIsArray($authentication->value);
        static::assertTrue($authentication->value['isPayment']);
        static::assertSame('example.com', $authentication->value['rpId']);
        static::assertInstanceOf(PaymentCurrencyAmount::class, $authentication->value['total']);
        static::assertInstanceOf(PaymentCredentialInstrument::class, $authentication->value['instrument']);
    }

    #[Test]
    public function outputCheckerAcceptsValidBrowserBoundSignature(): void
    {
        $handler = ExtensionOutputCheckerHandler::create();
        $handler->add(new PaymentExtensionOutputChecker());

        $inputs = new AuthenticationExtensions([PaymentExtension::register()]);
        $outputs = new AuthenticationExtensions([
            AuthenticationExtension::create('payment', $this->validBrowserBoundSignatureOutput()),
        ]);

        $handler->check($inputs, $outputs);
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function outputCheckerRejectsMissingBrowserBoundSignature(): void
    {
        $handler = ExtensionOutputCheckerHandler::create();
        $handler->add(new PaymentExtensionOutputChecker());

        $inputs = new AuthenticationExtensions([PaymentExtension::register()]);
        $outputs = new AuthenticationExtensions([
            AuthenticationExtension::create('payment', [
                'foo' => 'bar',
            ]),
        ]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('"browserBoundSignature"');

        $handler->check($inputs, $outputs);
    }

    #[Test]
    public function clientDataCollectorCatchesAmountTampering(): void
    {
        // Per W3C SPC §5.1, the transaction the user signs lives in
        // clientDataJSON.payment, NOT in the extension output. So amount
        // tampering is caught by PaymentClientDataCollector, not by
        // PaymentExtensionOutputChecker.
        $collector = new PaymentClientDataCollector($this->getSerializer());

        $tamperedClientData = $this->collectedClientDataWithPayment([
            'rpId' => 'example.com',
            'topOrigin' => 'https://merchant.example.com',
            'total' => [
                'currency' => 'USD',
                'value' => '9999.00',
            ],
            'instrument' => [
                'displayName' => 'Visa •••• 1234',
                'icon' => 'https://example.com/visa-icon.png',
            ],
            'payeeName' => 'Merchant Store',
            'payeeOrigin' => 'https://merchant.example.com',
        ]);

        $requestOptions = PublicKeyCredentialRequestOptions::create(
            'challenge',
            extensions: new AuthenticationExtensions([
                PaymentExtension::authenticate(
                    rpId: 'example.com',
                    topOrigin: 'https://merchant.example.com',
                    total: PaymentCurrencyAmount::create('USD', '1.00'),
                    instrument: PaymentCredentialInstrument::create(
                        'Visa •••• 1234',
                        'https://example.com/visa-icon.png',
                    ),
                    payeeName: 'Merchant Store',
                    payeeOrigin: 'https://merchant.example.com',
                ),
            ]),
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Payment total.value mismatch');

        $collector->verifyCollectedClientData(
            $tamperedClientData,
            $requestOptions,
            static::createStub(AuthenticatorAssertionResponse::class),
            'example.com',
        );
    }

    #[Test]
    public function multipleExtensionsCanCoexistWithPayment(): void
    {
        $extensions = new AuthenticationExtensions([
            AuthenticationExtension::create('appid', 'https://example.com'),
            PaymentExtension::register(),
            AuthenticationExtension::create('credProps', true),
        ]);

        static::assertCount(3, $extensions);
        static::assertTrue($extensions->has('appid'));
        static::assertTrue($extensions->has('payment'));
        static::assertTrue($extensions->has('credProps'));
    }

    /**
     * @return array{browserBoundSignature: array{signature: string}}
     */
    private function validBrowserBoundSignatureOutput(): array
    {
        return [
            'browserBoundSignature' => [
                // base64url("hello") = aGVsbG8
                'signature' => 'aGVsbG8',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $payment
     */
    private function collectedClientDataWithPayment(array $payment): CollectedClientData
    {
        $rawData = json_encode([
            'type' => 'payment.get',
            'challenge' => rtrim(strtr(base64_encode('challenge'), '+/', '-_'), '='),
            'origin' => 'https://example.com',
            'payment' => $payment,
        ], JSON_THROW_ON_ERROR);

        return CollectedClientData::create($rawData, json_decode($rawData, true));
    }
}
