# @web-auth/webauthn-stimulus

WebAuthn Stimulus controllers for passwordless authentication in web applications.

This package provides ready-to-use [Stimulus](https://stimulus.hotwired.dev/) controllers for implementing WebAuthn/FIDO2 authentication (passkeys) in your web applications. It wraps [@simplewebauthn/browser](https://simplewebauthn.dev/) to provide an easy-to-use interface for credential registration and authentication.

## Features

- 🔐 **Passwordless authentication** with WebAuthn/FIDO2
- 🔑 **Passkey support** (biometrics, security keys, platform authenticators)
- 🎯 **Three specialized controllers**: authentication, registration, and legacy combined
- 🌐 **Browser autofill support** (conditional UI)
- 📱 **Platform authenticator detection** (Face ID, Touch ID, Windows Hello)
- ⚡ **Event-driven architecture** for custom integrations
- 🎨 **Framework agnostic** (works with any Stimulus-enabled app)

## Installation

```bash
npm install @web-auth/webauthn-stimulus
```

### Dependencies

This package requires:

- `@hotwired/stimulus` ^3.0.0
- `@simplewebauthn/browser` ^13.2.0

These are listed as peer dependencies and should be installed in your project.

### Usage with Module Bundlers

If you're using a module bundler (webpack, Vite, etc.) without Symfony UX, you can import controllers directly:

```javascript
// Import individual controllers
import { AuthenticationController, RegistrationController } from '@web-auth/webauthn-stimulus';

// Or import specific ones
import AuthenticationController from '@web-auth/webauthn-stimulus/src/authentication-controller.js';

// Register with Stimulus
import { Application } from '@hotwired/stimulus';
const app = Application.start();
app.register('webauthn--authentication', AuthenticationController);
```

## Available Controllers

### 1. Authentication Controller (`authentication-controller.js`)

Handles user sign-in with existing credentials.

```html
<form
    data-controller="webauthn--authentication"
    data-webauthn--authentication-options-url-value="/auth/options"
    data-webauthn--authentication-result-url-value="/auth/verify"
    data-webauthn--authentication-conditional-ui-value="true"
    data-action="submit->webauthn--authentication#authenticate">
    <input
        type="text"
        name="username"
        autocomplete="username webauthn"
        data-webauthn--authentication-target="username" />
    <input type="hidden" data-webauthn--authentication-target="result" />
    <button type="submit">Sign In</button>
</form>
```

**Features:**

- Browser autofill support (conditional UI)
- Platform authenticator availability detection
- Flexible result handling (API or form submission)
- Optional redirect after success

### 2. Registration Controller (`registration-controller.js`)

Handles new credential registration (user sign-up).

```html
<form
    data-controller="webauthn--registration"
    data-webauthn--registration-options-url-value="/register/options"
    data-webauthn--registration-result-url-value="/register/verify"
    data-action="submit->webauthn--registration#register">
    <input type="text" name="username" data-webauthn--registration-target="username" />
    <input type="text" name="displayName" data-webauthn--registration-target="displayName" />
    <select name="attestation" data-webauthn--registration-target="attestation">
        <option value="none">None</option>
        <option value="direct">Direct</option>
    </select>
    <input type="hidden" data-webauthn--registration-target="result" />
    <button type="submit">Register</button>
</form>
```

**Features:**

- Configurable attestation level
- Resident key support
- User verification options
- Authenticator attachment preferences
- Auto-register mode (conditional create)

### 3. Legacy Controller (`controller.js`)

Combined controller for backward compatibility. Handles both registration and authentication.

```html
<form data-controller="webauthn">
    <!-- Registration -->
    <button data-action="webauthn#signup">Sign Up</button>

    <!-- Authentication -->
    <button data-action="webauthn#signin">Sign In</button>
</form>
```

## Configuration Values

### Common Values (all controllers)

| Value                | Type    | Description                    | Default  |
| -------------------- | ------- | ------------------------------ | -------- |
| `optionsUrl`         | String  | URL to fetch options from      | Required |
| `resultUrl`          | String  | URL to send result to          | Required |
| `submitViaForm`      | Boolean | Submit via form instead of API | `false`  |
| `successRedirectUri` | String  | Redirect URL after success     | -        |

### Authentication-specific Values

| Value                 | Type    | Description                  | Default |
| --------------------- | ------- | ---------------------------- | ------- |
| `conditionalUi`       | Boolean | Enable browser autofill      | `false` |
| `verifyAutofillInput` | Boolean | Verify autofill input exists | `true`  |

### Registration-specific Values

| Value          | Type    | Description               | Default |
| -------------- | ------- | ------------------------- | ------- |
| `autoRegister` | Boolean | Enable auto-register mode | `false` |

## Events

All controllers dispatch custom events for integration:

### Success Events

- `webauthn:connect` - Controller connected
- `webauthn:options:request` - Options requested
- `webauthn:options:success` - Options received
- `webauthn:authenticator:response` - Authenticator responded
- `webauthn:attestation:success` - Registration successful
- `webauthn:assertion:success` - Authentication successful

### Error Events

- `webauthn:unsupported` - WebAuthn not supported
- `webauthn:options:failure` - Failed to get options
- `webauthn:attestation:failure` - Registration failed
- `webauthn:assertion:failure` - Authentication failed

### Event Handling Example

```javascript
document.addEventListener('webauthn:assertion:success', (event) => {
    console.log('Authentication successful!', event.detail);
});

document.addEventListener('webauthn:assertion:failure', (event) => {
    console.error('Authentication failed:', event.detail.exception);
});
```

## Server-Side Integration

Your backend needs to provide two endpoints per operation:

### For Authentication

1. **Options endpoint** (`GET/POST`) - Returns `PublicKeyCredentialRequestOptions`
2. **Verification endpoint** (`POST`) - Verifies the authentication response

### For Registration

1. **Options endpoint** (`GET/POST`) - Returns `PublicKeyCredentialCreationOptions`
2. **Verification endpoint** (`POST`) - Verifies and stores the credential

See [@simplewebauthn/server](https://simplewebauthn.dev/docs/packages/server) for server-side implementation examples.

## Symfony Integration

This package is designed to work seamlessly with the [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework) Symfony bundle:

```bash
composer require web-auth/webauthn-stimulus
```

When installed via Composer with Symfony Flex, the controllers are automatically registered and available in your Twig templates:

```twig
<form {{ stimulus_controller('@web-auth/webauthn-stimulus/authentication') }}>
    {# ... #}
</form>
```

For detailed Symfony integration documentation, visit:

- [Bundle documentation](https://github.com/web-auth/webauthn-framework/tree/5.3.x/src/stimulus)
- [Main framework repository](https://github.com/web-auth/webauthn-framework)

## Browser Support

Requires browsers with WebAuthn support:

- Chrome/Edge 67+
- Firefox 60+
- Safari 13+
- Opera 54+

Check support at runtime:

```javascript
import { browserSupportsWebAuthn } from '@simplewebauthn/browser';

if (browserSupportsWebAuthn()) {
    // Show WebAuthn UI
}
```

## Examples

### With API Verification

```html
<form
    data-controller="webauthn--authentication"
    data-webauthn--authentication-options-url-value="/api/auth/options"
    data-webauthn--authentication-result-url-value="/api/auth/verify"
    data-webauthn--authentication-success-redirect-uri-value="/dashboard">
    <!-- Form fields -->
</form>
```

### With Form Submission

```html
<form
    data-controller="webauthn--registration"
    data-webauthn--registration-options-url-value="/register/options"
    data-webauthn--registration-submit-via-form-value="true">
    <input type="hidden" data-webauthn--registration-target="result" />
    <!-- Form fields -->
</form>
```

### With Browser Autofill

```html
<form data-controller="webauthn--authentication" data-webauthn--authentication-conditional-ui-value="true">
    <input
        type="text"
        name="username"
        autocomplete="username webauthn"
        data-webauthn--authentication-target="username" />
</form>
```

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Lint code
npm run lint

# Format code
npm run format
```

## Resources

- [WebAuthn Guide](https://webauthn.guide/) - Introduction to WebAuthn
- [SimpleWebAuthn Documentation](https://simplewebauthn.dev/) - Library documentation
- [Passkeys.dev](https://passkeys.dev/) - Passkey resources
- [FIDO Alliance](https://fidoalliance.org/) - WebAuthn standards

## License

MIT - See [LICENSE](LICENSE) file for details.

## Contributing

This is a sub-package of the [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework) monorepo.

Please submit issues and pull requests to the main repository:

- **Issues**: https://github.com/web-auth/webauthn-framework/issues
- **Pull Requests**: https://github.com/web-auth/webauthn-framework/pulls

## Credits

- **Author**: [Florent Morselli](https://github.com/Spomky)
- **Contributors**: [All contributors](https://github.com/web-auth/webauthn-framework/graphs/contributors)
