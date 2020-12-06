<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use function array_key_exists;
use Assert\Assertion;
use function is_array;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\PublicKeyCredentialOptions;

final class CustomSessionStorage implements OptionsStorage
{
    /**
     * @var string
     */
    private const SESSION_PARAMETER = 'FOO_BAR_SESSION_PARAMETER';

    public function store(Request $request, StoredData $data, ?Response $response = null): void
    {
        if (null === $response) {
            @trigger_error('Passing null as 3rd argument is deprecated since version 3.3 and will be mandatory in 4.0.', E_USER_DEPRECATED);
        }
        $session = $request->getSession();
        Assertion::notNull($session, 'This authentication method requires a session.');

        $session->set(self::SESSION_PARAMETER, ['options' => $data->getPublicKeyCredentialOptions(), 'userEntity' => $data->getPublicKeyCredentialUserEntity()]);
    }

    public function get(Request $request): StoredData
    {
        $session = $request->getSession();
        Assertion::notNull($session, 'This authentication method requires a session.');

        $sessionValue = $session->remove(self::SESSION_PARAMETER);
        if (!is_array($sessionValue) || !array_key_exists('options', $sessionValue) || !array_key_exists('userEntity', $sessionValue)) {
            throw new BadRequestHttpException('No public key credential options available for this session.');
        }

        $publicKeyCredentialRequestOptions = $sessionValue['options'];
        $userEntity = $sessionValue['userEntity'];

        if (!$publicKeyCredentialRequestOptions instanceof PublicKeyCredentialOptions) {
            throw new BadRequestHttpException('No public key credential options available for this session.');
        }

        return new StoredData($publicKeyCredentialRequestOptions, $userEntity);
    }
}
