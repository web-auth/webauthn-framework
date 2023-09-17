<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

/**
 * @deprecated since 4.6.0, to be removed in 5.0.0. Use {@link PublicKeyCredentialUserEntityRepositoryInterface} and {@link CanRegisterUserEntity} instead.
 * @infection-ignore-all
 */
interface PublicKeyCredentialUserEntityRepository extends PublicKeyCredentialUserEntityRepositoryInterface, CanRegisterUserEntity
{
}
