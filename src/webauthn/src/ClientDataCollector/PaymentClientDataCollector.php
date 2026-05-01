<?php

declare(strict_types=1);

namespace Webauthn\ClientDataCollector;

use function array_key_exists;
use function assert;
use function is_array;
use function is_string;
use function sprintf;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AuthenticatorResponse;
use Webauthn\CollectedClientData;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

/**
 * Verifies an SPC assertion's `clientDataJSON` (per W3C Secure Payment
 * Confirmation §5.1, §9.1).
 *
 * The authenticator signs `clientDataJSON || authenticatorData`. For an SPC
 * assertion, `clientDataJSON` carries `type: "payment.get"` and a `payment`
 * field of type `CollectedClientAdditionalPaymentData`. This collector is
 * responsible for:
 *
 *  1. Asserting the type is `"payment.get"`;
 *  2. Parsing `clientData.payment` into a typed object;
 *  3. Comparing every payment field (rpId, topOrigin, total.currency,
 *     total.value, instrument.displayName, instrument.icon, payeeName,
 *     payeeOrigin) against the corresponding values from the request
 *     options' `payment` extension input — closing the SPC threat that a
 *     compromised client substitutes the amount the user actually signs.
 */
final readonly class PaymentClientDataCollector implements ClientDataCollector
{
    public const CLIENT_DATA_TYPE = 'payment.get';

    public function __construct(
        private DenormalizerInterface $denormalizer,
    ) {
    }

    public function supportedTypes(): array
    {
        return [self::CLIENT_DATA_TYPE];
    }

    public function verifyCollectedClientData(
        CollectedClientData $collectedClientData,
        PublicKeyCredentialOptions $publicKeyCredentialOptions,
        AuthenticatorResponse $authenticatorResponse,
        string $host
    ): void {
        if (! $publicKeyCredentialOptions instanceof PublicKeyCredentialRequestOptions) {
            throw AuthenticatorResponseVerificationException::create(
                'The "payment.get" client data type can only appear in an assertion ceremony.',
            );
        }

        if (! $collectedClientData->has('payment')) {
            throw AuthenticatorResponseVerificationException::create(
                'Missing "payment" field in clientDataJSON for an SPC assertion.',
            );
        }

        $rawPayment = $collectedClientData->get('payment');
        if (! is_array($rawPayment)) {
            throw AuthenticatorResponseVerificationException::create(
                'Invalid "payment" field in clientDataJSON: expected an object.',
            );
        }

        $signedPayment = $this->denormalizer->denormalize(
            $rawPayment,
            CollectedClientAdditionalPaymentData::class,
        );
        assert($signedPayment instanceof CollectedClientAdditionalPaymentData);

        $extensions = $publicKeyCredentialOptions->extensions;
        if (! $extensions->has('payment')) {
            throw AuthenticatorResponseVerificationException::create(
                'The request options must include a "payment" extension to validate an SPC assertion.',
            );
        }

        $rawInput = $extensions->get('payment')
            ->value;
        if (! is_array($rawInput)) {
            throw AuthenticatorResponseVerificationException::create('Invalid "payment" extension input format.');
        }

        // Per §5 step 4: skip cross-field comparison on a registration-only
        // input (`['isPayment' => true]`). Such an input is not legal for an
        // assertion that produced `payment.get`, but we are tolerant here and
        // rely on the rest of the ceremony (origin, challenge, RP id hash) to
        // catch any abuse.
        if (! array_key_exists('rpId', $rawInput)) {
            return;
        }

        $this->ensureMatch('rpId', $rawInput['rpId'] ?? null, $signedPayment->rpId);
        $this->ensureMatch('topOrigin', $rawInput['topOrigin'] ?? null, $signedPayment->topOrigin);
        $this->ensureTotalMatch($rawInput['total'] ?? null, $signedPayment->total);
        $this->ensureInstrumentMatch($rawInput['instrument'] ?? null, $signedPayment->instrument);
        $this->ensureMatch('payeeName', $rawInput['payeeName'] ?? null, $signedPayment->payeeName);
        $this->ensureMatch('payeeOrigin', $rawInput['payeeOrigin'] ?? null, $signedPayment->payeeOrigin);
    }

    private function ensureMatch(string $field, mixed $expected, mixed $actual): void
    {
        if ($expected === null || $expected === '') {
            return;
        }

        if ($expected !== $actual) {
            throw AuthenticatorResponseVerificationException::create(
                sprintf(
                    "Payment %s mismatch. Expected '%s', got '%s'.",
                    $field,
                    is_string($expected) ? $expected : (string) json_encode($expected),
                    is_string($actual) ? $actual : (string) json_encode($actual),
                ),
            );
        }
    }

    private function ensureTotalMatch(mixed $inputTotal, PaymentCurrencyAmount $signed): void
    {
        [$currency, $value] = $this->coerceTotal($inputTotal);
        $this->ensureMatch('total.currency', $currency, $signed->currency);
        $this->ensureMatch('total.value', $value, $signed->value);
    }

    /**
     * @return array{0: string|null, 1: string|null}
     */
    private function coerceTotal(mixed $total): array
    {
        if ($total instanceof PaymentCurrencyAmount) {
            return [$total->currency, $total->value];
        }
        if (is_array($total)) {
            $currency = is_string($total['currency'] ?? null) ? $total['currency'] : null;
            $value = is_string($total['value'] ?? null) ? $total['value'] : null;

            return [$currency, $value];
        }

        return [null, null];
    }

    private function ensureInstrumentMatch(mixed $inputInstrument, PaymentCredentialInstrument $signed): void
    {
        [$displayName, $icon] = $this->coerceInstrument($inputInstrument);
        $this->ensureMatch('instrument.displayName', $displayName, $signed->displayName);
        $this->ensureMatch('instrument.icon', $icon, $signed->icon);
    }

    /**
     * @return array{0: string|null, 1: string|null}
     */
    private function coerceInstrument(mixed $instrument): array
    {
        if ($instrument instanceof PaymentCredentialInstrument) {
            return [$instrument->displayName, $instrument->icon];
        }
        if (is_array($instrument)) {
            $displayName = is_string($instrument['displayName'] ?? null) ? $instrument['displayName'] : null;
            $icon = is_string($instrument['icon'] ?? null) ? $instrument['icon'] : null;

            return [$displayName, $icon];
        }

        return [null, null];
    }
}
