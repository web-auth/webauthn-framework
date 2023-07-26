<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AuthenticationExtensions\ExtensionInputs;
use Webauthn\AuthenticationExtensions\ExtensionManager;
use function array_key_exists;
use const JSON_THROW_ON_ERROR;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Util\Base64;

final class PublicKeyCredentialRequestOptionsLoader
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

    public function createFromString(string $data): PublicKeyCredentialRequestOptions
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public function createFromArray(array $json): PublicKeyCredentialRequestOptions
    {
        array_key_exists('challenge', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "challenge" is missing.'
        );

        $allowCredentials = [];
        $allowCredentialList = $json['allowCredentials'] ?? [];
        foreach ($allowCredentialList as $allowCredential) {
            $allowCredentials[] = PublicKeyCredentialDescriptor::createFromArray($allowCredential);
        }

        $challenge = Base64::decode($json['challenge']);

        $extensionInputs = ExtensionInputs::create();
        if (isset($json['extensions'])) {
            $extensionInputs = $this->extensionManager->loadFromInput($json['extensions']);
        }

        return PublicKeyCredentialRequestOptions::create($challenge)
            ->setRpId($json['rpId'] ?? null)
            ->allowCredentials(...$allowCredentials)
            ->setUserVerification($json['userVerification'] ?? null)
            ->setTimeout($json['timeout'] ?? null)
            ->setExtensions($extensionInputs);
    }
}
