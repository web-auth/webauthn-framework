<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\PublicKeyCredentialDescriptor;

final class UserRepository
{
    private $users;

    public function __construct()
    {
        $this->users = [
            'admin' => new User('admin', ['ROLE_ADMIN', 'ROLE_USER'], [new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                \Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true)
            )]),
        ];
    }

    public function findByUsername(string $username): ?UserInterface
    {
        if (array_key_exists($username, $this->users)) {
            return $this->users[$username];
        }

        return null;
    }
}
