<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function array_key_exists;
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
     * @param string $credentialId Raw credential id bytes (the same bytes that appear in
     *                              {@see \Webauthn\PublicKeyCredentialDescriptor::$id}); the W3C spec
     *                              expects the key to be a base64url string. Pre-encode if you only
     *                              hold the base64url form.
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
