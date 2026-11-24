<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Ceremony state kept by the Relying Party between the options request and the authenticator response.
 *
 * `$ceremonyOrigin` records the origin the ceremony was started on, so that the response can be checked against that
 * single origin instead of the whole allow list.
 *
 * `$scope` names the endpoint of the bundle that issued the options: `firewall.<firewall name>`,
 * `controllers.request.<name>` or `controllers.creation.<name>`. A result endpoint bound to a scope refuses an item
 * issued under another one, so that a challenge obtained from one endpoint cannot be redeemed against the requirements
 * of another (user verification, attestation conveyance, allowed credentials). An item stored without scope, for
 * instance by application code, is accepted as before.
 *
 * Both are plain properties carrying a default rather than promoted readonly ones, and the class is not `readonly` for
 * that reason alone: items live in the cache for the duration of a ceremony, so a deployment hands this class payloads
 * serialized before the properties existed. `unserialize()` restores the declared default for a missing plain
 * property, where a promoted one would stay uninitialized and make every read raise an `Error`. The matching Rector
 * rules are skipped for this file in `.ci-tools/rector.php`.
 *
 * @see https://github.com/w3c/webauthn/issues/2466
 */
final class Item
{
    private ?string $ceremonyOrigin = null;

    private ?string $scope = null;

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

    /**
     * Returns a copy of this item bound to the scope of the endpoint that issued the options.
     */
    public function withScope(?string $scope): self
    {
        $item = clone $this;
        $item->scope = $scope;

        return $item;
    }

    /**
     * Scope of the endpoint that issued the options, or `null` when the item was stored by a code path that does not
     * record it.
     */
    public function getScope(): ?string
    {
        return $this->scope;
    }

    /**
     * Whether a result endpoint bound to `$scope` may verify a response against these options. An endpoint without
     * scope, and an item without scope, keep the behavior of earlier versions.
     */
    public function isRedeemableBy(?string $scope): bool
    {
        return $scope === null || $this->scope === null || $this->scope === $scope;
    }
}
