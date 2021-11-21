<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

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

    public function store(Request $request, StoredData $data, ?Response $response = null): void
    {
        if (null === $response) {
            @trigger_error('Passing null as 3rd argument is deprecated since version 3.3 and will be mandatory in 4.0.', E_USER_DEPRECATED);
        }
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
