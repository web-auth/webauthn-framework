<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\CollectedClientPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class PaymentDataSerializationTest extends AbstractTestCase
{
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
