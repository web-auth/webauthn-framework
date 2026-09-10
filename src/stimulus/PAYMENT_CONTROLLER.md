# Payment Controller — Secure Payment Confirmation

Stimulus controller for [W3C Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation/).
It is a thin extension of `AuthenticationController` (so all of its events,
values and behaviour apply) that adds two payment-specific concerns:

1. The `payment` extension input is forwarded to the user agent unchanged —
   the browser displays its own SPC confirmation UI from the
   server-supplied transaction details.
2. The `browserBoundSignature.signature` returned in
   `clientExtensionResults.payment` is an `ArrayBuffer`; the controller
   encodes it to base64url before sending the credential to your verifier
   so the JSON payload is well-formed.

## ⚠️ Security model

Per W3C SPC §5.1, what the user actually signs is `clientDataJSON.payment` —
the values returned to the relying party in the assertion's client data.
Those values come from the **server-issued** request options
(`PublicKeyCredentialRequestOptions.extensions.payment`). Never let the
browser supply payment data: any client-controlled field can be tampered
with. Build your transaction server-side, store its details indexed by an
opaque ID, and only pass that ID through HTML.

## Installation

```bash
npm install @web-auth/webauthn-stimulus
```

## Usage

```html
<form data-controller="webauthn--payment"
      data-action="submit->webauthn--payment#authenticate"
      data-webauthn--payment-options-url-value="/payment/options"
      data-webauthn--payment-result-url-value="/payment/verify">

    <!-- Display payment info from server-side data -->
    <p>Amount: <?= htmlspecialchars($transaction->getFormattedAmount()) ?></p>

    <input type="hidden" data-webauthn--payment-target="result">
    <button type="submit">Confirm payment</button>
</form>
```

The `webauthn--payment-options-url-value` endpoint must return a JSON
`PublicKeyCredentialRequestOptions` whose `extensions.payment` field is the
serialised `PaymentExtension::authenticate(...)` produced server-side.

## Configuration

`PaymentController` inherits all of [`AuthenticationController`](./assets/src/authentication-controller.js)'s
values, targets, actions and events. Defaults for the URL values change to
match the SPC convention:

| Value         | Default            |
|---------------|--------------------|
| `optionsUrl`  | `/payment/options` |
| `resultUrl`   | `/payment/verify`  |

All other inherited values (`submitViaForm`, `successRedirectUri`,
`conditionalUi`, `verifyAutofillInput`) behave identically to the
authentication controller — see its docblock for details.

## Events

The controller dispatches the same events as `AuthenticationController`,
prefixed with `webauthn:authentication:` (not `webauthn:payment:`). Filter
on the originating controller in the listener:

```javascript
form.addEventListener('webauthn:authentication:credential', (event) => {
    // event.detail.credential.clientExtensionResults.payment.browserBoundSignature.signature
    // is already a base64url string — ready to be sent to the verifier.
});
```

## Server side

The Symfony bundle wires the SPC validation pieces automatically:

- `PaymentClientDataCollector` is registered as a `ClientDataCollector` for
  the `payment.get` `clientDataJSON` type. It compares the signed
  `clientDataJSON.payment` field-by-field with the request options'
  `payment` extension input — closing the SPC threat that a compromised
  client substitutes the amount the user actually signs.
- `PaymentExtensionOutputChecker` is added to the
  `ExtensionOutputCheckerHandler`. It asserts that
  `clientExtensionResults.payment.browserBoundSignature` is present and
  well-formed.

A standard `AuthenticatorAssertionResponseValidator->check(...)` call
therefore performs full SPC validation:

```php
$publicKeyCredentialSource = $this->authenticatorAssertionResponseValidator->check(
    publicKeyCredentialSource: $credentialSource,
    authenticatorAssertionResponse: $credential->response,
    publicKeyCredentialRequestOptions: $storedOptions,
    host: 'example.com',
    userHandle: $userId,
);
```

For full server documentation including the request-side
`PaymentExtension::authenticate(...)` builder and the data-structure
catalogue, see [docs/secure-payment-confirmation.md](../../docs/secure-payment-confirmation.md).
