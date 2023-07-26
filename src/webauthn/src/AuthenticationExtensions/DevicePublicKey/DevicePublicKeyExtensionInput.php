<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions\DevicePublicKey;

use Webauthn\AuthenticationExtensions\ExtensionInput;
use Webauthn\PublicKeyCredentialCreationOptions;

final class DevicePublicKeyExtensionInput implements ExtensionInput
{
    /**
     * @param array<string> $attestationFormats
     */
    private function __construct(
        public readonly string $attestation,
        public readonly array $attestationFormats = [],
    ) {
    }

    /**
     * @param array<string> $attestationFormats
     */
    public static function create(
        string $attestation = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        array $attestationFormats = [],
    ): self
    {
        return new self($attestation, $attestationFormats);
    }

    public function identifier(): string
    {
        return 'devicePubKey';
    }

    /**
     * @return array<string, string|string[]>
     */
    public function jsonSerialize(): array
    {
        return [
            'attestation' => $this->attestation,
            'attestationFormats' => $this->attestationFormats,
        ];
    }
}
