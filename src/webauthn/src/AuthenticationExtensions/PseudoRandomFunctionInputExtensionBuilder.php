<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function array_key_exists;
use function count;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function trigger_deprecation;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * Fluent builder for the WebAuthn `prf` extension input.
 *
 * The Pseudo-Random Function (PRF) extension lets the relying party have a secret
 * derived on the client, bound both to the credential and to the salts the relying
 * party provides. The inputs assembled by this builder become `extensions.prf` on
 * the {@see \Webauthn\PublicKeyCredentialCreationOptions} or
 * {@see \Webauthn\PublicKeyCredentialRequestOptions} returned to the browser; the
 * Stimulus base controller decodes them to ArrayBuffers before the
 * `navigator.credentials.{create,get}()` call.
 *
 * Typical use, server-driven encryption key derivation:
 * ```php
 * $options->extensions[] = PseudoRandomFunctionInputExtensionBuilder::create()
 *     ->withInputs($salt) // 32 random bytes from your KMS / generated per user
 *     ->build();
 * ```
 *
 * ## PRF results stay on the client
 *
 * The results are returned to the page in
 * `credential.getClientExtensionResults().prf.results` and nowhere else. W3C
 * WebAuthn Level 3 requires that authenticator extension outputs MUST NOT contain
 * cleartext PRF outputs, precisely because the authenticator data is signed and is
 * therefore forwarded to the relying party server together with the assertion.
 *
 * Two consequences for server-side code:
 *
 *  - the PRF result is never available to this library, and asking for it here is
 *    a design mistake: only the page can read it, typically to derive an
 *    encryption key with Web Crypto;
 *  - a readable `prf` entry among the authenticator extension outputs is a red
 *    flag, not usable key material. {@see PseudoRandomFunctionOutputChecker} is
 *    the opt-in enforcement of that requirement.
 *
 * ## Authenticator support
 *
 * The extension is abstract over the authenticator implementation. An authenticator
 * may serve it through the CTAP `hmac-secret` extension or through any other
 * interface, as long as the behaviour observed by the relying party is identical,
 * so PRF availability cannot be derived from CTAP support alone. Whether a given
 * ceremony was served at all is reported by the client in `prf.enabled` and by the
 * presence of `prf.results`.
 *
 * One shape of input is worth calling out: evaluating the PRF for more than one
 * credential within a single `navigator.credentials.get()` ceremony is not
 * universally supported. {@see self::requiresMultipleCredentialEvaluation()}
 * reports whether the configured inputs fall into that case.
 *
 * @see https://www.w3.org/TR/webauthn-3/#prf-extension
 */
final class PseudoRandomFunctionInputExtensionBuilder
{
    /**
     * @var array{eval?: array{first: string, second?: string}, evalByCredential?: array<string, array{first: string, second?: string}>}
     */
    private array $values = [];

    private function __construct()
    {
    }

    public static function create(): self
    {
        return new self();
    }

    /**
     * Set the global PRF inputs. Used during registration when the credential is
     * not yet known, and as a fallback during authentication when a credential is
     * not covered by {@see self::withCredentialInputs()}.
     *
     * @param string $first  Raw salt bytes (typically 32). Encoded to base64url before transport.
     * @param string|null $second Optional second raw salt bytes; produces `results.second` in the browser output.
     */
    public function withInputs(string $first, null|string $second = null): self
    {
        $eval = [
            'first' => Base64UrlSafe::encodeUnpadded($first),
        ];
        if ($second !== null) {
            $eval['second'] = Base64UrlSafe::encodeUnpadded($second);
        }
        $this->values['eval'] = $eval;

        return $this;
    }

    /**
     * Set per-credential PRF inputs. Preferred during authentication so each
     * credential can be queried with its own salt (e.g. a salt rotated alongside
     * a re-encrypted blob).
     *
     * Calling this twice with two distinct credential ids puts the ceremony in the
     * multi-credential case, which not every authenticator can serve, see the class
     * docblock and {@see self::requiresMultipleCredentialEvaluation()}.
     *
     * @param string $credentialId Raw credential id bytes, as stored in a credential record. The specification
     *                              requires the keys of the `evalByCredential` map to be the base64url encoding of the
     *                              credential id, so the encoding is done here and MUST NOT be done by the caller.
     * @param string $first  Raw salt bytes for this credential.
     * @param string|null $second Optional second raw salt bytes.
     */
    public function withCredentialInputs(string $credentialId, string $first, null|string $second = null): self
    {
        $eval = [
            'first' => Base64UrlSafe::encodeUnpadded($first),
        ];
        if ($second !== null) {
            $eval['second'] = Base64UrlSafe::encodeUnpadded($second);
        }
        if (! array_key_exists('evalByCredential', $this->values)) {
            $this->values['evalByCredential'] = [];
        }
        $this->values['evalByCredential'][Base64UrlSafe::encodeUnpadded($credentialId)] = $eval;

        return $this;
    }

    /**
     * Whether the configured inputs ask the authenticator to evaluate the PRF for
     * more than one credential within a single `navigator.credentials.get()`
     * ceremony.
     *
     * Returns `true` when `evalByCredential` carries inputs for at least two
     * distinct credentials. That case needs an authenticator able to answer
     * several evaluations in one assertion, which older CTAP authenticators
     * (`hmac-secret` without the CTAP2.2 `hmac-secret-mc` addition) cannot do.
     * Returns `false` for the single-credential and `eval`-only configurations,
     * which every PRF-capable authenticator can serve at assertion time.
     *
     * Note: evaluating the PRF during `navigator.credentials.create()` is subject
     * to the same kind of limitation. The builder cannot tell which ceremony its
     * output will be attached to, so callers using {@see self::withInputs()} during
     * registration are responsible for remembering that constraint themselves.
     */
    public function requiresMultipleCredentialEvaluation(): bool
    {
        return count($this->values['evalByCredential'] ?? []) > 1;
    }

    /**
     * @deprecated since 5.4, use {@see self::requiresMultipleCredentialEvaluation()} instead. The `prf` extension is
     *             abstract over the authenticator implementation, so naming the CTAP `hmac-secret-mc` extension in this
     *             API was inaccurate. Will be removed in 6.0.
     */
    public function requiresHmacSecretMc(): bool
    {
        trigger_deprecation(
            'web-auth/webauthn-lib',
            '5.4',
            'The method "%s::requiresHmacSecretMc()" is deprecated and will be removed in 6.0. Please use "%s::requiresMultipleCredentialEvaluation()" instead.',
            self::class,
            self::class
        );

        return $this->requiresMultipleCredentialEvaluation();
    }

    /**
     * @throws AuthenticationExtensionException if neither `eval` nor `evalByCredential`
     *                                          inputs were provided, since sending an empty PRF
     *                                          extension to the browser is a programming
     *                                          error that would silently produce no result.
     */
    public function build(): PseudoRandomFunctionInputExtension
    {
        if ($this->values === []) {
            throw AuthenticationExtensionException::create(
                'Cannot build a PRF extension without any input. Call withInputs() or withCredentialInputs() first.'
            );
        }

        return new PseudoRandomFunctionInputExtension('prf', $this->values);
    }
}
