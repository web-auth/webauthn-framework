<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function array_key_exists;
use function count;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * Fluent builder for the WebAuthn `prf` extension input.
 *
 * The Pseudo-Random Function (PRF) extension lets the relying party derive an
 * authenticator-bound, salt-bound secret on the client. The inputs assembled by
 * this builder become `extensions.prf` on the {@see \Webauthn\PublicKeyCredentialCreationOptions}
 * or {@see \Webauthn\PublicKeyCredentialRequestOptions} returned to the browser; the
 * Stimulus base controller decodes them to ArrayBuffers before the
 * `navigator.credentials.{create,get}()` call.
 *
 * Typical use — server-driven encryption key derivation:
 * ```php
 * $options->extensions[] = PseudoRandomFunctionInputExtensionBuilder::create()
 *     ->withInputs($salt) // 32 random bytes from your KMS / generated per user
 *     ->build();
 * ```
 *
 * ## CTAP2.2 `hmac-secret-mc`
 *
 * PRF maps to the CTAP authenticator extension `hmac-secret`. CTAP2.2 added a
 * variant `hmac-secret-mc` that lifts two limitations of the original:
 *
 *  - PRF results can be returned during `navigator.credentials.create()` (so
 *    the relying party can derive a key at registration time, not just at
 *    authentication).
 *  - `evalByCredential` may target more than one credential in a single
 *    `navigator.credentials.get()` ceremony.
 *
 * The wire format does not change — the user agent picks `hmac-secret` vs
 * `hmac-secret-mc` based on what the inputs require. {@see self::requiresHmacSecretMc()}
 * lets callers introspect whether the configured inputs definitely require an
 * `hmac-secret-mc`-capable authenticator (the multi-credential case detectable
 * from the builder state).
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
     * Calling this twice with two distinct credential ids puts the ceremony in
     * the multi-credential case, which requires the authenticator to support
     * the CTAP2.2 `hmac-secret-mc` extension — see the class docblock.
     *
     * @param string $credentialId Base64url-encoded credential id (same encoding used as the
     *                              JSON key on the wire). If you hold the raw bytes, pre-encode
     *                              with `Base64UrlSafe::encodeUnpadded()` first.
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
        $this->values['evalByCredential'][$credentialId] = $eval;

        return $this;
    }

    /**
     * Whether the configured inputs require an authenticator that implements the
     * CTAP2.2 `hmac-secret-mc` extension (as opposed to plain `hmac-secret`).
     *
     * Returns `true` when `evalByCredential` carries inputs for more than one
     * credential — i.e. the multi-credential case `hmac-secret-mc` was
     * introduced for. Returns `false` for the single-credential / `eval`-only
     * configurations, which a regular `hmac-secret` authenticator can serve at
     * `navigator.credentials.get()` time.
     *
     * Note: the spec also requires `hmac-secret-mc` whenever PRF results are
     * requested at `navigator.credentials.create()` time. The builder cannot
     * tell which ceremony its output will be attached to, so callers using
     * {@see self::withInputs()} during registration are responsible for
     * remembering that constraint themselves.
     */
    public function requiresHmacSecretMc(): bool
    {
        return count($this->values['evalByCredential'] ?? []) > 1;
    }

    /**
     * @throws AuthenticationExtensionException if neither `eval` nor `evalByCredential`
     *                                          inputs were provided — sending an empty PRF
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
