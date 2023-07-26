<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions\DevicePublicKey;

use Webauthn\AuthenticationExtensions\ExtensionOutput;

final class DevicePublicKeyExtensionOutput implements ExtensionOutput
{
    private function __construct(
        public readonly string $aaguid,
        public readonly string $dpk,
        public readonly int $scope,
        public readonly string $nonce,
        public readonly string $fmt,
        public readonly array $attStmt,
        public readonly bool $epAtt,
    )
    {
    }

    public static function create(
        string $aaguid,
        string $dpk,
        int $scope,
        string $nonce,
        string $fmt,
        array $attStmt,
        bool $epAtt,
    ): self
    {
        return new self($aaguid, $dpk, $scope, $nonce, $fmt, $attStmt, $epAtt);
    }

    public function identifier(): string
    {
        return 'devicePubKey';
    }
}
