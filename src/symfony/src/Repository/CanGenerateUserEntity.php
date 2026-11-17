<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialUserEntity;

interface CanGenerateUserEntity
{
    /**
     * Creates the entity of a new user from the username and display name submitted by a client.
     *
     * The entity must carry a new user handle: random, never derived from the username or from other personal data, and
     * never the handle of an existing user. `RequestBodyUserEntityGuesser` calls this method for requests that are not
     * authenticated and refuses an entity whose user handle already exists.
     *
     * @see https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy
     */
    public function generateUserEntity(?string $username, ?string $displayName): PublicKeyCredentialUserEntity;
}
