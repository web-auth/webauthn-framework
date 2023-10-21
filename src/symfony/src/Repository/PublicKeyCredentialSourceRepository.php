<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;

/**
 * @deprecated since 4.6.0, to be removed in 5.0.0. Use  Webauthn\Bundle\Repository\DoctrineCredentialSourceRepository instead.
 * @infection-ignore-all
 */
class PublicKeyCredentialSourceRepository extends DoctrineCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface
{
}
