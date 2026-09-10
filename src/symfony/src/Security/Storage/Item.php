<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Ceremony state kept by the Relying Party between the options request and the
 * authenticator response.
 *
 * `$ceremonyOrigin` records the origin the ceremony was started on, so that the
 * response can be checked against that single origin instead of the whole
 * allow list.
 *
 * It is a plain property carrying a default rather than a promoted readonly
 * one, and the class is not `readonly` for that reason alone: items live in the
 * cache for the duration of a ceremony, so a deployment hands this class
 * payloads serialized before the property existed. `unserialize()` restores the
 * declared default for a missing plain property, where a promoted one would
 * stay uninitialized and make every read raise an `Error`. The matching Rector
 * rules are skipped for this file in `.ci-tools/rector.php`.
 *
 * @see https://github.com/w3c/webauthn/issues/2466
 */
final class Item
{
    private ?string $ceremonyOrigin = null;

    public function __construct(
        private readonly PublicKeyCredentialOptions $publicKeyCredentialOptions,
        private readonly ?PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        ?string $ceremonyOrigin = null,
    ) {
        $this->ceremonyOrigin = $ceremonyOrigin;
    }

    public static function create(
        PublicKeyCredentialOptions $publicKeyCredentialOptions,
        ?PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        ?string $ceremonyOrigin = null,
    ): self {
        return new self($publicKeyCredentialOptions, $publicKeyCredentialUserEntity, $ceremonyOrigin);
    }

    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        return $this->publicKeyCredentialOptions;
    }

    public function getPublicKeyCredentialUserEntity(): ?PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }

    /**
     * Origin (`scheme://host[:port]`) the ceremony was started on, or `null`
     * when the ceremony was stored by a code path that does not record it.
     */
    public function getCeremonyOrigin(): ?string
    {
        return $this->ceremonyOrigin;
    }
}
