/**
 * @web-auth/webauthn-stimulus
 * WebAuthn Stimulus Controllers
 */

export { default as AuthenticationController } from './authentication-controller.js';
export { default as PaymentController } from './payment-controller.js';
export { default as RegistrationController } from './registration-controller.js';
export { default as WebauthnController } from './controller.js';
export { default as BaseController } from './base-controller.js';
export {
    dispatchAllAcceptedCredentials,
    dispatchCurrentUserDetails,
    dispatchSignals,
    dispatchUnknownCredential,
} from './signals.js';
