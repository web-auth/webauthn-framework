<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use Assert\Assertion;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Webauthn\Bundle\Security\Storage\RequestOptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final class CustomSessionStorage implements RequestOptionsStorage
{
    /**
     * @var string
     */
    private const SESSION_PARAMETER = 'FOO_BAR_SESSION_PARAMETER';

    public function store(Request $request, StoredData $data): void
    {
        $session = $request->getSession();
        Assertion::notNull($session, 'This authentication method requires a session.');

        $session->set(self::SESSION_PARAMETER, ['options' => $data->getPublicKeyCredentialRequestOptions(), 'userEntity' => $data->getPublicKeyCredentialUserEntity()]);
    }

    public function get(Request $request): StoredData
    {
        $session = $request->getSession();
        Assertion::notNull($session, 'This authentication method requires a session.');

        $sessionValue = $session->remove(self::SESSION_PARAMETER);
        if (!\is_array($sessionValue) || !\array_key_exists('options', $sessionValue) || !\array_key_exists('userEntity', $sessionValue)) {
            throw new BadRequestHttpException('No public key credential request options available for this session.');
        }

        $publicKeyCredentialRequestOptions = $sessionValue['options'];
        $userEntity = $sessionValue['userEntity'];

        if (!$publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions) {
            throw new BadRequestHttpException('No public key credential request options available for this session.');
        }
        if (!$userEntity instanceof PublicKeyCredentialUserEntity) {
            throw new BadRequestHttpException('No user entity available for this session.');
        }

        return new StoredData($publicKeyCredentialRequestOptions, $userEntity);
    }
}
