<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AuthenticationExtensions\ExtensionInputs;
use Webauthn\AuthenticationExtensions\ExtensionManager;
use function array_key_exists;
use function is_array;
use const JSON_THROW_ON_ERROR;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Util\Base64;

final class PublicKeyCredentialCreationOptionsLoader
{
    public function __construct(
        private readonly ExtensionManager $extensionManager
    )
    {
    }

    public static function create(null|ExtensionManager $extensionManager = null): self
    {
        return new self($extensionManager ?? ExtensionManager::create());
    }

    public function createFromString(string $data): PublicKeyCredentialCreationOptions
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    public function createFromArray(array $json): PublicKeyCredentialCreationOptions
    {
        array_key_exists('rp', $json) || throw InvalidDataException::create($json, 'Invalid input. "rp" is missing.');
        array_key_exists('pubKeyCredParams', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "pubKeyCredParams" is missing.'
        );
        is_array($json['pubKeyCredParams']) || throw InvalidDataException::create(
            $json,
            'Invalid input. "pubKeyCredParams" is not an array.'
        );
        array_key_exists('challenge', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "challenge" is missing.'
        );
        array_key_exists('attestation', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "attestation" is missing.'
        );
        array_key_exists('user', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "user" is missing.'
        );

        $pubKeyCredParams = [];
        foreach ($json['pubKeyCredParams'] as $pubKeyCredParam) {
            if (! is_array($pubKeyCredParam)) {
                continue;
            }
            $pubKeyCredParams[] = PublicKeyCredentialParameters::createFromArray($pubKeyCredParam);
        }
        $excludeCredentials = [];
        if (isset($json['excludeCredentials'])) {
            foreach ($json['excludeCredentials'] as $excludeCredential) {
                $excludeCredentials[] = PublicKeyCredentialDescriptor::createFromArray($excludeCredential);
            }
        }

        $challenge = Base64::decode($json['challenge']);

        $extensionInputs = ExtensionInputs::create();
        if (isset($json['extensions'])) {
            $extensionInputs = $this->extensionManager->loadFromInput($json['extensions']);
        }

        return PublicKeyCredentialCreationOptions
            ::create(
                PublicKeyCredentialRpEntity::createFromArray($json['rp']),
                PublicKeyCredentialUserEntity::createFromArray($json['user']),
                $challenge,
                $pubKeyCredParams
            )
                ->setTimeout($json['timeout'] ?? null)
                ->excludeCredentials(...$excludeCredentials)
                ->setAuthenticatorSelection(
                    isset($json['authenticatorSelection']) ? AuthenticatorSelectionCriteria::createFromArray(
                        $json['authenticatorSelection']
                    ) : null
                )
                ->setAttestation($json['attestation'] ?? null)
                ->setExtensions($extensionInputs);
    }
}
