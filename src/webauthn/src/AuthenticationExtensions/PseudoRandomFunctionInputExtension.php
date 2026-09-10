<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

/**
 * The `prf` extension INPUT, as produced by {@see PseudoRandomFunctionInputExtensionBuilder}.
 *
 * There is no matching output class on purpose: the PRF results are a client-side
 * secret, delivered to the page in `credential.getClientExtensionResults().prf` and
 * never carried to the relying party server. See the builder docblock for the full
 * rationale and {@see PseudoRandomFunctionOutputChecker} for the opt-in check that
 * rejects a `prf` entry in the authenticator extension outputs.
 *
 * @see https://www.w3.org/TR/webauthn-3/#prf-extension
 */
final class PseudoRandomFunctionInputExtension extends AuthenticationExtension
{
}
