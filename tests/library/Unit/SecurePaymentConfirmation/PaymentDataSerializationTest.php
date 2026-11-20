<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentRegistrationData;
use Webauthn\SecurePaymentConfirmation\CollectedClientPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class PaymentDataSerializationTest extends AbstractTestCase
{
    /**
     * The `browserBoundPublicKey` of a Chrome payment: an ES256 COSE_Key, encoded in base64url.
     */
    private const CHROME_BROWSER_BOUND_PUBLIC_KEY = 'pQECAyYgASFYIOUsBC35x2TSfRGkSeKL_uHMiWe_ptKFneJmAnIsaO4RIlggQWPJ1LAnV7OxxGq9ovhnXOqIQB7-7X6cduprsGgqEHk';

    #[Test]
    public function paymentCurrencyAmountRoundTrip(): void
    {
        $amount = PaymentCurrencyAmount::create('USD', '99.99');

        $json = $this->serialize($amount);
        $deserialized = $this->getSerializer()
            ->deserialize($json, PaymentCurrencyAmount::class, 'json');

        static::assertJsonStringEqualsJsonString('{"currency":"USD","value":"99.99"}', $json);
        static::assertEquals($amount, $deserialized);
    }

    #[Test]
    public function paymentCredentialInstrumentRoundTrip(): void
    {
        $instrument = PaymentCredentialInstrument::create(
            'Visa •••• 1234',
            'https://example.com/visa-icon.png',
            true
        );

        $json = $this->serialize($instrument);
        $deserialized = $this->getSerializer()
            ->deserialize($json, PaymentCredentialInstrument::class, 'json');

        static::assertJsonStringEqualsJsonString(
            '{"displayName":"Visa •••• 1234","icon":"https://example.com/visa-icon.png","iconMustBeShown":true}',
            $json
        );
        static::assertEquals($instrument, $deserialized);
    }

    #[Test]
    public function paymentCredentialInstrumentWithDetailsRoundTrip(): void
    {
        $instrument = PaymentCredentialInstrument::create(
            'Visa •••• 1234',
            'https://example.com/visa-icon.png',
            true,
            '1234'
        );

        $json = $this->serialize($instrument);
        $deserialized = $this->getSerializer()
            ->deserialize($json, PaymentCredentialInstrument::class, 'json');

        static::assertStringContainsString('"details":"1234"', $json);
        static::assertEquals($instrument, $deserialized);
    }

    #[Test]
    public function additionalPaymentDataRoundTrip(): void
    {
        $paymentData = CollectedClientAdditionalPaymentData::create(
            rpId: 'example.com',
            topOrigin: 'https://merchant.example.com',
            total: PaymentCurrencyAmount::create('USD', '150.00'),
            instrument: PaymentCredentialInstrument::create(
                'MasterCard •••• 5678',
                'https://example.com/mc-icon.png',
                false
            ),
            payeeName: 'Merchant Store',
            payeeOrigin: 'https://merchant.example.com',
        );

        $json = $this->serialize($paymentData);
        $deserialized = $this->getSerializer()
            ->deserialize($json, CollectedClientAdditionalPaymentData::class, 'json');

        static::assertJsonStringEqualsJsonString(
            '{
                "rpId": "example.com",
                "topOrigin": "https://merchant.example.com",
                "total": {"currency": "USD", "value": "150.00"},
                "instrument": {"displayName": "MasterCard •••• 5678", "icon": "https://example.com/mc-icon.png", "iconMustBeShown": false},
                "payeeName": "Merchant Store",
                "payeeOrigin": "https://merchant.example.com"
            }',
            $json
        );
        static::assertEquals($paymentData, $deserialized);
    }

    #[Test]
    public function collectedClientPaymentDataRoundTrip(): void
    {
        $additionalData = CollectedClientAdditionalPaymentData::create(
            rpId: 'store.com',
            topOrigin: 'https://top.example.com',
            total: PaymentCurrencyAmount::create('EUR', '75.50'),
            instrument: PaymentCredentialInstrument::create(
                'Amex •••• 9012',
                'https://example.com/amex-icon.png'
            ),
            payeeName: 'Online Store',
            payeeOrigin: 'https://store.example.com',
        );
        $paymentData = CollectedClientPaymentData::create($additionalData);

        $json = $this->serialize($paymentData);
        $deserialized = $this->getSerializer()
            ->deserialize($json, CollectedClientPaymentData::class, 'json');

        static::assertJsonStringEqualsJsonString(
            '{
                "payment": {
                    "rpId": "store.com",
                    "topOrigin": "https://top.example.com",
                    "total": {"currency": "EUR", "value": "75.50"},
                    "instrument": {"displayName": "Amex •••• 9012", "icon": "https://example.com/amex-icon.png", "iconMustBeShown": true},
                    "payeeName": "Online Store",
                    "payeeOrigin": "https://store.example.com"
                }
            }',
            $json
        );
        static::assertEquals($paymentData, $deserialized);
    }

    #[Test]
    public function additionalPaymentDataWithoutOptionalPayeeFields(): void
    {
        $json = '{
            "rpId": "example.com",
            "topOrigin": "https://merchant.example.com",
            "total": {"currency": "USD", "value": "50.00"},
            "instrument": {"displayName": "Card", "icon": "https://example.com/icon.png"}
        }';

        $deserialized = $this->getSerializer()
            ->deserialize($json, CollectedClientAdditionalPaymentData::class, 'json');

        static::assertSame('example.com', $deserialized->rpId);
        static::assertSame('https://merchant.example.com', $deserialized->topOrigin);
        static::assertSame('', $deserialized->payeeName);
        static::assertSame('', $deserialized->payeeOrigin);
    }

    #[Test]
    public function theBrowserBoundPublicKeyIsTheBase64UrlEncodingOfACoseKey(): void
    {
        $json = sprintf('{
            "rpId": "example.com",
            "topOrigin": "https://merchant.example.com",
            "total": {"currency": "USD", "value": "50.00"},
            "instrument": {"displayName": "Card", "icon": "https://example.com/icon.png"},
            "browserBoundPublicKey": "%s"
        }', self::CHROME_BROWSER_BOUND_PUBLIC_KEY);

        $deserialized = $this->getSerializer()
            ->deserialize($json, CollectedClientAdditionalPaymentData::class, 'json');

        static::assertEquals(
            BrowserBoundPublicKey::create(Base64UrlSafe::decodeNoPadding(self::CHROME_BROWSER_BOUND_PUBLIC_KEY)),
            $deserialized->browserBoundPublicKey
        );
        static::assertSame("\xa5", $deserialized->browserBoundPublicKey?->publicKey[0]);
        static::assertSame(
            self::CHROME_BROWSER_BOUND_PUBLIC_KEY,
            json_decode($this->serialize($deserialized), true, 512, JSON_THROW_ON_ERROR)['browserBoundPublicKey']
        );
    }

    #[Test]
    public function theBrowserBoundPublicKeyIsOptional(): void
    {
        $deserialized = $this->getSerializer()
            ->deserialize(
                '{"rpId":"example.com","topOrigin":"https://merchant.example.com","total":{"currency":"USD","value":"1"},"instrument":{"displayName":"C","icon":"https://example.com/icon.png"}}',
                CollectedClientAdditionalPaymentData::class,
                'json'
            );

        static::assertNull($deserialized->browserBoundPublicKey);
    }

    #[Test]
    public function theRegistrationDataCarriesTheBrowserBoundPublicKey(): void
    {
        $json = sprintf('{"browserBoundPublicKey": "%s"}', self::CHROME_BROWSER_BOUND_PUBLIC_KEY);

        $deserialized = $this->getSerializer()
            ->deserialize($json, CollectedClientAdditionalPaymentRegistrationData::class, 'json');

        static::assertEquals(
            BrowserBoundPublicKey::create(Base64UrlSafe::decodeNoPadding(self::CHROME_BROWSER_BOUND_PUBLIC_KEY)),
            $deserialized->browserBoundPublicKey
        );
        static::assertSame(-7, $deserialized->browserBoundPublicKey?->algorithm());
        static::assertJsonStringEqualsJsonString($json, $this->serialize($deserialized));
    }

    #[Test]
    public function theBrowserBoundPublicKeyOfTheRegistrationDataIsOptional(): void
    {
        $deserialized = $this->getSerializer()
            ->deserialize('{}', CollectedClientAdditionalPaymentRegistrationData::class, 'json');

        static::assertNull($deserialized->browserBoundPublicKey);
        static::assertSame([], $this->getSerializer()->normalize($deserialized));
        static::assertEquals(
            $deserialized,
            $this->getSerializer()
                ->deserialize(
                    $this->serialize($deserialized),
                    CollectedClientAdditionalPaymentRegistrationData::class,
                    'json'
                )
        );
    }

    #[Test]
    public function theOtherMembersOfTheRegistrationDataAreIgnored(): void
    {
        $deserialized = $this->getSerializer()
            ->deserialize(
                sprintf(
                    '{"rpId":"example.com","browserBoundPublicKey":"%s","isPayment":true}',
                    self::CHROME_BROWSER_BOUND_PUBLIC_KEY
                ),
                CollectedClientAdditionalPaymentRegistrationData::class,
                'json'
            );

        static::assertSame(-7, $deserialized->browserBoundPublicKey?->algorithm());
        static::assertJsonStringEqualsJsonString(
            sprintf('{"browserBoundPublicKey":"%s"}', self::CHROME_BROWSER_BOUND_PUBLIC_KEY),
            $this->serialize($deserialized)
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedRegistrationData(): iterable
    {
        yield 'not an object' => ['"payment"', 'expected an array'];
        yield 'browserBoundPublicKey as an object' => [
            '{"browserBoundPublicKey":{"publicKey":"pQECAyYgAQ","algorithm":-7}}',
            'Invalid browserBoundPublicKey',
        ];
        yield 'empty browserBoundPublicKey' => ['{"browserBoundPublicKey":""}', 'browser-bound public key'];
        yield 'browserBoundPublicKey that is not base64url' => [
            '{"browserBoundPublicKey":"#not base64url#"}',
            'Invalid data submitted',
        ];
    }

    #[Test]
    #[DataProvider('provideMalformedRegistrationData')]
    public function malformedRegistrationDataIsRejected(string $json, string $message): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage($message);

        $this->getSerializer()
            ->deserialize($json, CollectedClientAdditionalPaymentRegistrationData::class, 'json');
    }

    #[Test]
    public function theClientDataOfARegistrationGivesTheRegistrationDictionary(): void
    {
        $clientData = $this->getSerializer()
            ->denormalize([
                'type' => 'webauthn.create',
                'challenge' => 'Y2hhbGxlbmdl',
                'origin' => 'https://example.com',
                'payment' => [
                    'browserBoundPublicKey' => self::CHROME_BROWSER_BOUND_PUBLIC_KEY,
                ],
            ], CollectedClientPaymentData::class);

        static::assertInstanceOf(CollectedClientAdditionalPaymentRegistrationData::class, $clientData->payment);
        static::assertSame(-7, $clientData->payment->browserBoundPublicKey?->algorithm());
    }

    #[Test]
    public function theClientDataOfARegistrationWithoutBrowserBoundKeyGivesTheRegistrationDictionary(): void
    {
        $clientData = $this->getSerializer()
            ->denormalize([
                'type' => 'webauthn.create',
                'challenge' => 'Y2hhbGxlbmdl',
                'origin' => 'https://example.com',
                'payment' => [],
            ], CollectedClientPaymentData::class);

        static::assertInstanceOf(CollectedClientAdditionalPaymentRegistrationData::class, $clientData->payment);
        static::assertNull($clientData->payment->browserBoundPublicKey);
    }

    #[Test]
    public function theTypeOfTheClientDataPrevailsOverTheMembersOfThePayment(): void
    {
        $clientData = $this->getSerializer()
            ->denormalize([
                'type' => 'webauthn.create',
                'payment' => [
                    'rpId' => 'example.com',
                    'browserBoundPublicKey' => self::CHROME_BROWSER_BOUND_PUBLIC_KEY,
                ],
            ], CollectedClientPaymentData::class);

        static::assertInstanceOf(CollectedClientAdditionalPaymentRegistrationData::class, $clientData->payment);
    }

    #[Test]
    public function theClientDataOfAPaymentGivesTheAuthenticationDictionary(): void
    {
        $clientData = $this->getSerializer()
            ->denormalize([
                'type' => 'payment.get',
                'challenge' => 'Y2hhbGxlbmdl',
                'origin' => 'https://example.com',
                'payment' => [
                    'rpId' => 'example.com',
                    'topOrigin' => 'https://merchant.example.com',
                    'total' => [
                        'currency' => 'USD',
                        'value' => '50.00',
                    ],
                    'instrument' => [
                        'displayName' => 'Card',
                        'icon' => 'https://example.com/icon.png',
                    ],
                    'browserBoundPublicKey' => self::CHROME_BROWSER_BOUND_PUBLIC_KEY,
                ],
            ], CollectedClientPaymentData::class);

        static::assertInstanceOf(CollectedClientAdditionalPaymentData::class, $clientData->payment);
        static::assertSame(-7, $clientData->payment->browserBoundPublicKey?->algorithm());
    }

    #[Test]
    public function theClientDataOfAPaymentWithOnlyABrowserBoundPublicKeyIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('"rpId"');

        $this->getSerializer()
            ->denormalize([
                'type' => 'payment.get',
                'payment' => [
                    'browserBoundPublicKey' => self::CHROME_BROWSER_BOUND_PUBLIC_KEY,
                ],
            ], CollectedClientPaymentData::class);
    }

    #[Test]
    public function collectedClientPaymentDataWithRegistrationDataRoundTrip(): void
    {
        $paymentData = CollectedClientPaymentData::create(
            CollectedClientAdditionalPaymentRegistrationData::create(
                BrowserBoundPublicKey::create(Base64UrlSafe::decodeNoPadding(self::CHROME_BROWSER_BOUND_PUBLIC_KEY))
            )
        );

        $json = $this->serialize($paymentData);
        $deserialized = $this->getSerializer()
            ->deserialize($json, CollectedClientPaymentData::class, 'json');

        static::assertJsonStringEqualsJsonString(
            sprintf('{"payment":{"browserBoundPublicKey":"%s"}}', self::CHROME_BROWSER_BOUND_PUBLIC_KEY),
            $json
        );
        static::assertEquals($paymentData, $deserialized);
    }

    #[Test]
    public function historicalRpFieldIsAccepted(): void
    {
        $json = '{
            "rp": "example.com",
            "topOrigin": "https://merchant.example.com",
            "total": {"currency": "USD", "value": "50.00"},
            "instrument": {"displayName": "Card", "icon": "https://example.com/icon.png"}
        }';

        $deserialized = $this->getSerializer()
            ->deserialize($json, CollectedClientAdditionalPaymentData::class, 'json');

        static::assertSame('example.com', $deserialized->rpId);
    }

    #[Test]
    public function instrumentDefaultsIconMustBeShownToTrue(): void
    {
        $json = '{"displayName": "Card", "icon": "https://example.com/icon.png"}';

        $deserialized = $this->getSerializer()
            ->deserialize($json, PaymentCredentialInstrument::class, 'json');

        static::assertTrue($deserialized->iconMustBeShown);
        static::assertNull($deserialized->details);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedCurrencyAmount(): iterable
    {
        yield 'missing currency' => ['{"value":"10.00"}', 'currency'];
        yield 'missing value' => ['{"currency":"USD"}', 'value'];
        yield 'currency wrong type' => ['{"currency":42,"value":"10.00"}', 'currency'];
        yield 'value wrong type' => ['{"currency":"USD","value":1000}', 'value'];
    }

    #[Test]
    #[DataProvider('provideMalformedCurrencyAmount')]
    public function malformedCurrencyAmountIsRejected(string $json, string $expectedField): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage(sprintf('"%s"', $expectedField));

        $this->getSerializer()
            ->deserialize($json, PaymentCurrencyAmount::class, 'json');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedInstrument(): iterable
    {
        yield 'missing displayName' => ['{"icon":"https://example.com/icon.png"}', 'displayName'];
        yield 'missing icon' => ['{"displayName":"Card"}', 'icon'];
        yield 'wrong iconMustBeShown type' => [
            '{"displayName":"Card","icon":"https://example.com/icon.png","iconMustBeShown":"yes"}',
            'iconMustBeShown',
        ];
    }

    #[Test]
    #[DataProvider('provideMalformedInstrument')]
    public function malformedInstrumentIsRejected(string $json, string $expectedField): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage(sprintf('"%s"', $expectedField));

        $this->getSerializer()
            ->deserialize($json, PaymentCredentialInstrument::class, 'json');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedAdditionalPaymentData(): iterable
    {
        yield 'missing rpId/rp' => [
            '{"topOrigin":"https://x","total":{"currency":"USD","value":"1"},"instrument":{"displayName":"C","icon":"https://example.com/icon.png"}}',
            'rpId',
        ];
        yield 'missing topOrigin' => [
            '{"rpId":"x","total":{"currency":"USD","value":"1"},"instrument":{"displayName":"C","icon":"https://example.com/icon.png"}}',
            'topOrigin',
        ];
        yield 'missing total' => [
            '{"rpId":"x","topOrigin":"https://x","instrument":{"displayName":"C","icon":"https://example.com/icon.png"}}',
            'total',
        ];
        yield 'missing instrument' => [
            '{"rpId":"x","topOrigin":"https://x","total":{"currency":"USD","value":"1"}}',
            'instrument',
        ];
        yield 'browserBoundPublicKey as an object' => [
            '{"rpId":"x","topOrigin":"https://x","total":{"currency":"USD","value":"1"},"instrument":{"displayName":"C","icon":"https://example.com/icon.png"},"browserBoundPublicKey":{"publicKey":"pQECAyYgAQ","algorithm":-7}}',
            'browserBoundPublicKey',
        ];
        yield 'empty browserBoundPublicKey' => [
            '{"rpId":"x","topOrigin":"https://x","total":{"currency":"USD","value":"1"},"instrument":{"displayName":"C","icon":"https://example.com/icon.png"},"browserBoundPublicKey":""}',
            'browser-bound public key',
        ];
    }

    #[Test]
    #[DataProvider('provideMalformedAdditionalPaymentData')]
    public function malformedAdditionalPaymentDataIsRejected(string $json, string $expectedField): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage($expectedField);

        $this->getSerializer()
            ->deserialize($json, CollectedClientAdditionalPaymentData::class, 'json');
    }

    #[Test]
    public function malformedCollectedClientPaymentDataIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('"payment"');

        $this->getSerializer()
            ->deserialize('{"foo":"bar"}', CollectedClientPaymentData::class, 'json');
    }

    private function serialize(object $object): string
    {
        return $this->getSerializer()
            ->serialize($object, 'json', [
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                AbstractObjectNormalizer::SKIP_UNINITIALIZED_VALUES => true,
            ]);
    }
}
