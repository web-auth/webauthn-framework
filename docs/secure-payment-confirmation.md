# Secure Payment Confirmation (SPC)

Secure Payment Confirmation (SPC) is a Web API that allows customers to authenticate with a payment provider using WebAuthn. This provides a streamlined and secure checkout experience.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [PHP Usage](#php-usage)
  - [Creating Payment Extension](#creating-payment-extension)
  - [Validating Payment Data](#validating-payment-data)
  - [Data Structures](#data-structures)
- [JavaScript/Stimulus Usage](#javascriptstimulus-usage)
- [Complete Example](#complete-example)
- [W3C Specification](#w3c-specification)

## Overview

SPC enables customers to authenticate card payments using WebAuthn, providing:

- **Strong authentication** via FIDO2/WebAuthn
- **User-friendly experience** with biometric authentication
- **Regulatory compliance** (e.g., PSD2 SCA in Europe)
- **Fraud prevention** through device-bound credentials

## Installation

The SPC support is included in the core `webauthn-framework/webauthn` package:

```bash
composer require web-auth/webauthn-framework
```

For Stimulus controllers (optional):

```bash
npm install @web-auth/webauthn-stimulus
```

## PHP Usage

### Creating Payment Extension

To request a payment confirmation, create a payment extension when building your `PublicKeyCredentialRequestOptions`:

```php
use Webauthn\AuthenticationExtensions\PaymentExtension;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\PublicKeyCredentialRequestOptions;

// Create payment data
$amount = PaymentCurrencyAmount::create('USD', '99.99');
$instrument = PaymentCredentialInstrument::create(
    displayName: 'Visa •••• 1234',
    icon: 'https://example.com/visa-icon.png',
    iconMustBeShown: true
);

// Create payment extension
$paymentExtension = PaymentExtension::authenticate(
    rpId: 'example.com',
    topOrigin: 'https://merchant.example.com',
    total: $amount,
    instrument: $instrument,
    payeeName: 'Merchant Store',
    payeeOrigin: 'https://merchant.example.com',
);

// Add to authentication options
$publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
    challenge: random_bytes(32),
    rpId: 'example.com',
    extensions: new AuthenticationExtensions([$paymentExtension])
);
```

### Validating Payment Data

W3C SPC §5.1 splits the verification work in two:

1. **`clientDataJSON.payment` (signed by the authenticator)** carries the
   transaction data the user actually confirmed. It is validated by
   `PaymentClientDataCollector`, registered against the `payment.get`
   client data type. This is what closes the SPC threat of a malicious
   client substituting the amount the user signs.
2. **`clientExtensionResults.payment.browserBoundSignature`** carries the
   browser-bound signature. Its structural presence is enforced by
   `PaymentExtensionOutputChecker`. Cryptographic verification requires
   the previously-stored `BrowserBoundPublicKey` (returned during
   registration as `clientData.payment.browserBoundPublicKey`) and is
   left to the relying party.

The Symfony bundle wires both pieces automatically: as soon as you enable
the bundle, `PaymentClientDataCollector` is registered alongside
`WebauthnAuthenticationCollector` in the `ClientDataCollectorManager`, and
`PaymentExtensionOutputChecker` is added to the `ExtensionOutputCheckerHandler`.
Standalone usage:

```php
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticationExtensions\PaymentExtensionOutputChecker;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\ClientDataCollector\ClientDataCollectorManager;
use Webauthn\ClientDataCollector\PaymentClientDataCollector;
use Webauthn\ClientDataCollector\WebauthnAuthenticationCollector;

$clientDataManager = new ClientDataCollectorManager([
    new WebauthnAuthenticationCollector(),
    new PaymentClientDataCollector($serializer),
]);

$extensionHandler = ExtensionOutputCheckerHandler::create();
$extensionHandler->add(new PaymentExtensionOutputChecker());

$factory = new CeremonyStepManagerFactory();
$factory->setClientDataCollectorManager($clientDataManager);
$factory->setExtensionOutputCheckerHandler($extensionHandler);
```

### Data Structures

#### PaymentCurrencyAmount

Represents the transaction amount:

```php
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

$amount = PaymentCurrencyAmount::create(
    currency: 'USD',  // ISO 4217 currency code
    value: '99.99'    // Amount as string
);

// Properties are readonly
echo $amount->currency; // 'USD'
echo $amount->value;    // '99.99'
```

#### PaymentCredentialInstrument

Represents the payment instrument (e.g., credit card):

```php
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;

$instrument = PaymentCredentialInstrument::create(
    displayName: 'Visa •••• 1234',
    icon: 'https://example.com/visa-icon.png',
    iconMustBeShown: true  // Optional, defaults to true
);
```

#### CollectedClientAdditionalPaymentData

Contains the payment data collected from the client:

```php
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;

$additionalData = CollectedClientAdditionalPaymentData::create(
    rpId: 'example.com',
    topOrigin: 'https://merchant.example.com',
    total: $amount,
    instrument: $instrument,
    payeeName: 'Merchant Store',
    payeeOrigin: 'https://merchant.example.com',
);
```

#### CollectedClientPaymentData

Top-level wrapper for the additional payment data:

```php
use Webauthn\SecurePaymentConfirmation\CollectedClientPaymentData;

$clientPaymentData = CollectedClientPaymentData::create($additionalData);
```

## JavaScript/Stimulus Usage

### Using the Payment Controller

The Stimulus payment controller simplifies SPC integration on the client side.

**SECURITY NOTICE:** For security reasons, payment details (amount, payee, etc.) are NOT passed via HTML attributes, as these can be tampered with by the client. Instead, you pass a secure `transaction-id`, and the server fetches the actual payment details from its database.

```html
<form data-controller="webauthn--payment"
      data-action="submit->webauthn--payment#confirmPayment"
      data-webauthn--payment-options-url-value="/api/payment/options"
      data-webauthn--payment-result-url-value="/api/payment/verify"
      data-webauthn--payment-transaction-id-value="txn_abc123def456">

    <h2>Confirm Payment</h2>
    <!-- Display payment details from server-side data -->
    <p>Amount: <strong><?= htmlspecialchars($transaction->getFormattedAmount()) ?></strong></p>
    <p>Merchant: <strong><?= htmlspecialchars($transaction->getPayeeName()) ?></strong></p>
    <p>Payment Method: <strong><?= htmlspecialchars($transaction->getInstrumentDisplay()) ?></strong></p>

    <input type="hidden" data-webauthn--payment-target="result">
    <button type="submit">Confirm Payment</button>
</form>
```

### Controller Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `optionsUrl` | String | `/payment/options` | URL to fetch payment options |
| `resultUrl` | String | `/payment/verify` | URL to verify payment result |
| `transactionId` | String | - | **Secure transaction ID** (server fetches payment details) |
| `submitViaForm` | Boolean | `false` | Submit credential via form instead of API |
| `successRedirectUri` | String | - | URI to redirect to on success |

**Security Note:** Payment details (amount, payee, merchant) are **intentionally NOT configurable** via HTML attributes to prevent client-side tampering. The server must fetch these from its database using the `transactionId`.

### Controller Events

The payment controller dispatches several custom events:

```javascript
// Connection event
document.addEventListener('webauthn:payment:connect', (event) => {
    console.log('Payment controller connected');
    console.log('Transaction ID:', event.detail.transactionId);
});

// Options request/response events
document.addEventListener('webauthn:payment:options:request', (event) => {
    console.log('Requesting payment options for transaction:', event.detail.data.transactionId);
});

document.addEventListener('webauthn:payment:options:success', (event) => {
    console.log('Payment options received', event.detail.options);
});

document.addEventListener('webauthn:payment:options:error', (event) => {
    console.error('Failed to get payment options', event.detail.error);
});

// Credential received event
document.addEventListener('webauthn:payment:credential', (event) => {
    console.log('Payment credential created', event.detail.credential);
});

// Verification events
document.addEventListener('webauthn:payment:verify:request', (event) => {
    console.log('Verifying payment credential', event.detail.credential);
});

document.addEventListener('webauthn:payment:verify:success', (event) => {
    console.log('Payment verified successfully', event.detail.result);
});

document.addEventListener('webauthn:payment:verify:error', (event) => {
    console.error('Payment verification failed', event.detail.error);
});

// Error event
document.addEventListener('webauthn:payment:error', (event) => {
    console.error('Payment error', event.detail.error);
    if (event.detail.code) {
        console.error('Error code:', event.detail.code);
    }
});

// Unsupported browser
document.addEventListener('webauthn:unsupported', () => {
    alert('Your browser does not support WebAuthn');
});
```

## Complete Example

### Backend (PHP)

```php
<?php

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\AuthenticationExtensions\PaymentExtension;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;

class PaymentController
{
    public function options(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        // SECURITY: Fetch payment details from database using transaction ID
        // This prevents client-side tampering of amounts/payee
        $transactionId = $data['transactionId'] ?? null;
        if (!$transactionId) {
            return new JsonResponse(['error' => 'Transaction ID required'], 400);
        }

        // Get transaction from secure database
        $transaction = $this->transactionRepository->findOneBy(['id' => $transactionId]);
        if (!$transaction || $transaction->getUserId() !== $this->getUser()->getId()) {
            return new JsonResponse(['error' => 'Transaction not found'], 404);
        }

        // Verify transaction is in pending state
        if ($transaction->getStatus() !== 'pending') {
            return new JsonResponse(['error' => 'Transaction already processed'], 400);
        }

        // Create payment extension with SERVER-VALIDATED data
        $amount = PaymentCurrencyAmount::create(
            $transaction->getCurrency(),
            $transaction->getAmount()
        );

        $instrument = PaymentCredentialInstrument::create(
            $transaction->getPaymentMethod()->getDisplayName(),
            $transaction->getPaymentMethod()->getIconUrl()
        );

        $paymentExtension = PaymentExtension::authenticate(
            rpId: 'example.com',
            topOrigin: $transaction->getMerchantOrigin(),
            total: $amount,
            instrument: $instrument,
            payeeName: $transaction->getPayeeName(),
            payeeOrigin: $transaction->getPayeeOrigin(),
        );

        // Create authentication options
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: 'example.com',
            allowCredentials: $this->getUserCredentials(),
            extensions: new AuthenticationExtensions([$paymentExtension])
        );

        // Store challenge and transaction ID in session for verification
        $_SESSION['payment_challenge'] = base64_encode($options->challenge);
        $_SESSION['payment_transaction_id'] = $transactionId;

        return new JsonResponse($options);
    }

    public function verify(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        // Deserialize and verify the credential
        $publicKeyCredential = $this->serializer->deserialize(
            json_encode($data),
            PublicKeyCredential::class,
            'json'
        );

        // Verify the assertion. The bundle has wired both the
        // PaymentClientDataCollector (validates clientDataJSON.payment) and
        // the PaymentExtensionOutputChecker (validates browserBoundSignature
        // is present), so the standard validator call is enough.
        $publicKeyCredentialSource = $this->authenticatorAssertionResponseValidator->check(
            publicKeyCredentialSource: $this->findCredentialSource($publicKeyCredential->id),
            authenticatorAssertionResponse: $publicKeyCredential->response,
            publicKeyCredentialRequestOptions: $this->getStoredOptions(),
            host: 'example.com',
            userHandle: $this->getCurrentUserId(),
        );

        // Process payment
        $this->processPayment($publicKeyCredentialSource);

        return new JsonResponse(['verified' => true]);
    }
}
```

### Frontend (HTML + Stimulus)

```html
<!DOCTYPE html>
<html>
<head>
    <title>Secure Payment</title>
</head>
<body>
    <div class="payment-container">
        <h1>Checkout</h1>

        <?php
        // Fetch transaction from secure database
        $transaction = $transactionRepository->find($transactionId);
        ?>

        <form data-controller="webauthn--payment"
              data-action="submit->webauthn--payment#confirmPayment"
              data-webauthn--payment-options-url-value="/api/payment/options"
              data-webauthn--payment-result-url-value="/api/payment/verify"
              data-webauthn--payment-transaction-id-value="<?= htmlspecialchars($transaction->getId()) ?>"
              data-webauthn--payment-success-redirect-uri-value="/payment/success">

            <div class="order-summary">
                <h2>Order Summary</h2>
                <!-- Display from server-side data, NOT from HTML attributes -->
                <p>Total: <strong><?= htmlspecialchars($transaction->getFormattedAmount()) ?></strong></p>
                <p>Merchant: <strong><?= htmlspecialchars($transaction->getPayeeName()) ?></strong></p>
            </div>

            <div class="payment-method">
                <h3>Payment Method</h3>
                <img src="<?= htmlspecialchars($transaction->getPaymentMethod()->getIconUrl()) ?>"
                     alt="<?= htmlspecialchars($transaction->getPaymentMethod()->getBrand()) ?>"
                     width="40">
                <span><?= htmlspecialchars($transaction->getPaymentMethod()->getDisplayName()) ?></span>
            </div>

            <button type="submit" class="btn-primary">
                Confirm Payment with Biometric
            </button>

            <div class="security-notice">
                <p>🔒 This payment will be authenticated using your device's biometric sensor</p>
            </div>
        </form>
    </div>

    <script type="module">
        // Listen for payment events
        document.addEventListener('webauthn:payment:error', (event) => {
            alert('Payment failed: ' + event.detail.error.message);
        });

        document.addEventListener('webauthn:payment:verify:success', () => {
            console.log('Payment verified successfully!');
        });
    </script>
</body>
</html>
```

## W3C Specification

This implementation follows the [W3C Secure Payment Confirmation specification](https://www.w3.org/TR/secure-payment-confirmation/).

Key features implemented:

- ✅ Payment extension for WebAuthn
- ✅ PaymentCredentialInstrument data structure
- ✅ PaymentCurrencyAmount data structure
- ✅ CollectedClientPaymentData verification
- ✅ Extension output validation
- ✅ Required field validation (rpId, total, instrument)
- ✅ Payee information validation (payeeName/payeeOrigin)

## Browser Support

SPC is supported in:

- Chrome 105+ (Desktop and Android)
- Edge 105+
- Opera 91+

Check browser support at runtime:

```javascript
import { browserSupportsWebAuthn } from '@simplewebauthn/browser';

if (browserSupportsWebAuthn()) {
    // SPC is supported
}
```

## Security Considerations

### Critical Security Measures

1. **NEVER trust client-side payment data**
   - Payment amounts, payee names, and merchant details must NEVER come from HTML attributes or JavaScript
   - Always fetch these from your secure server-side database using a transaction ID
   - The Stimulus controller is designed to only send a `transactionId` - do not modify it to accept payment details

2. **Server-side validation is mandatory**
   - The framework validates the signed `clientDataJSON.payment` field against your request via `PaymentClientDataCollector` and asserts the `browserBoundSignature` is present via `PaymentExtensionOutputChecker`.
   - Verify the transaction belongs to the authenticated user
   - Check the transaction status (must be "pending")
   - Validate the amount hasn't been modified

3. **Transaction ID security**
   - Generate cryptographically secure transaction IDs (e.g., `bin2hex(random_bytes(16))`)
   - Store transaction state in your database with user association
   - Implement transaction expiry (e.g., 15 minutes)
   - Mark transactions as "completed" or "cancelled" after processing

4. **Standard WebAuthn security**
   - Use HTTPS - SPC requires a secure context
   - Verify the challenge matches what was sent to the client
   - Check the RP ID matches your domain
   - Validate the payee origin matches the expected merchant
   - Store credentials securely using proper key management

### Example: Secure Transaction Flow

```php
// 1. Create transaction in database (server-side only)
$transaction = new Transaction();
$transaction->setId(bin2hex(random_bytes(16))); // Secure ID
$transaction->setUserId($currentUser->getId());
$transaction->setAmount('99.99');
$transaction->setCurrency('USD');
$transaction->setPayeeName('Merchant Store');
$transaction->setStatus('pending');
$transaction->setExpiresAt(new DateTime('+15 minutes'));
$entityManager->persist($transaction);
$entityManager->flush();

// 2. Render page with transaction ID only
echo '<form data-webauthn--payment-transaction-id-value="' .
     htmlspecialchars($transaction->getId()) . '">';

// 3. In options endpoint: Fetch from database
$transaction = $repository->findOneBy([
    'id' => $transactionId,
    'userId' => $currentUser->getId(),
    'status' => 'pending'
]);

if (!$transaction || $transaction->isExpired()) {
    return new JsonResponse(['error' => 'Invalid transaction'], 400);
}

// Use $transaction data for payment extension (NOT client data!)
```

### Why This Matters

**Attack scenario without this protection:**
1. User initiates payment for $10.00
2. Attacker modifies HTML: `data-amount-value="0.01"`
3. Without server validation, user pays only $0.01

**Protection with transaction ID:**
1. User initiates payment for $10.00
2. Server creates transaction with ID `txn_abc123` storing amount $10.00
3. Attacker can modify HTML attributes, but server ignores them
4. Server always uses database amount ($10.00) from transaction ID
5. Payment is processed for the correct amount ✅

## Troubleshooting

### Payment extension not present in response

Ensure the payment extension is properly configured in your `PublicKeyCredentialRequestOptions` and that the browser supports SPC.

### Payee name/origin mismatch

Check that the request options' `payment` extension carries the same `rpId`, `topOrigin`, `total`, `instrument` and `payee*` values that the user actually saw — `PaymentClientDataCollector` compares them field-by-field with what is signed in `clientDataJSON.payment`.

### Browser doesn't show payment UI

Verify:
- Browser supports SPC (Chrome 105+)
- Page is served over HTTPS
- Payment extension is correctly formatted
- User has registered a credential with the payment extension

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

## License

This library is released under the MIT License. See [LICENSE](../LICENSE) for details.
