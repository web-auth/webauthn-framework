<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use Webauthn\PublicKeyCredentialParameters;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\SecurePaymentConfirmation\PaymentEntityLogo;

/**
 * W3C Secure Payment Confirmation §5: `payment` extension factory.
 *
 * - {@see register()} produces the extension to attach to a registration
 *   ceremony (`PublicKeyCredentialCreationOptions`). It carries only
 *   `isPayment: true` plus the optional `browserBoundPubKeyCredParams`.
 * - {@see authenticate()} produces the extension to attach to an assertion
 *   ceremony (`PublicKeyCredentialRequestOptions`). It carries the full
 *   transaction payload that the user agent will display in the SPC
 *   confirmation UI and that the authenticator will sign as
 *   `clientDataJSON.payment`.
 */
final class PaymentExtension extends AuthenticationExtension
{
    /**
     * @param PublicKeyCredentialParameters[]|null $browserBoundPubKeyCredParams
     */
    public static function register(?array $browserBoundPubKeyCredParams = null): AuthenticationExtension
    {
        $value = [
            'isPayment' => true,
        ];
        if ($browserBoundPubKeyCredParams !== null) {
            $value['browserBoundPubKeyCredParams'] = $browserBoundPubKeyCredParams;
        }

        return self::create('payment', $value);
    }

    /**
     * @param PaymentEntityLogo[]                  $paymentEntitiesLogos
     * @param PublicKeyCredentialParameters[]|null $browserBoundPubKeyCredParams
     */
    public static function authenticate(
        string $rpId,
        string $topOrigin,
        PaymentCurrencyAmount $total,
        PaymentCredentialInstrument $instrument,
        string $payeeName = '',
        string $payeeOrigin = '',
        array $paymentEntitiesLogos = [],
        ?array $browserBoundPubKeyCredParams = null,
    ): AuthenticationExtension {
        $value = [
            'isPayment' => true,
            'rpId' => $rpId,
            'topOrigin' => $topOrigin,
            'total' => $total,
            'instrument' => $instrument,
            'payeeName' => $payeeName,
            'payeeOrigin' => $payeeOrigin,
        ];
        if ($paymentEntitiesLogos !== []) {
            $value['paymentEntitiesLogos'] = $paymentEntitiesLogos;
        }
        if ($browserBoundPubKeyCredParams !== null) {
            $value['browserBoundPubKeyCredParams'] = $browserBoundPubKeyCredParams;
        }

        return self::create('payment', $value);
    }
}
