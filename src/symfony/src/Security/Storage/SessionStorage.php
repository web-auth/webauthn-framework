<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use function array_key_exists;
use function is_array;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final class SessionStorage implements OptionsStorage
{
    /**
     * @var string
     */
    private const SESSION_PARAMETER = 'WEBAUTHN_PUBLIC_KEY_OPTIONS';

    public function store(Request $request, StoredData $data, Response $response): void
    {
        $session = $request->getSession();
        $session->set(self::SESSION_PARAMETER, ['options' => $data->getPublicKeyCredentialOptions(), 'userEntity' => $data->getPublicKeyCredentialUserEntity()]);
    }

    public function get(Request $request): StoredData
    {
        $session = $request->getSession();
        $sessionValue = $session->remove(self::SESSION_PARAMETER);
        if (!is_array($sessionValue) || !array_key_exists('options', $sessionValue) || !array_key_exists('userEntity', $sessionValue)) {
            throw new BadRequestHttpException('No public key credential options available for this session.');
        }

        $publicKeyCredentialRequestOptions = $sessionValue['options'];
        $userEntity = $sessionValue['userEntity'];

        if (!$publicKeyCredentialRequestOptions instanceof PublicKeyCredentialOptions) {
            throw new BadRequestHttpException('No public key credential options available for this session.');
        }
        if (null !== $userEntity && !$userEntity instanceof PublicKeyCredentialUserEntity) {
            throw new BadRequestHttpException('No user entity available for this session.');
        }

        return new StoredData($publicKeyCredentialRequestOptions, $userEntity);
    }
}
