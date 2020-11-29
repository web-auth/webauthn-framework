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

namespace Webauthn\MetadataService;

/**
 * @deprecated "The class is deprecated since v3.3 and will be an interface in v4.0"
 */
abstract class AuthenticatorStatus implements AuthenticatorStatusInterface
{
    public static function list(): array
    {
        return [
            AuthenticatorStatusInterface::NOT_FIDO_CERTIFIED,
            AuthenticatorStatusInterface::FIDO_CERTIFIED,
            AuthenticatorStatusInterface::USER_VERIFICATION_BYPASS,
            AuthenticatorStatusInterface::ATTESTATION_KEY_COMPROMISE,
            AuthenticatorStatusInterface::USER_KEY_REMOTE_COMPROMISE,
            AuthenticatorStatusInterface::USER_KEY_PHYSICAL_COMPROMISE,
            AuthenticatorStatusInterface::UPDATE_AVAILABLE,
            AuthenticatorStatusInterface::REVOKED,
            AuthenticatorStatusInterface::SELF_ASSERTION_SUBMITTED,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L1,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L1PLUS,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L2,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L2PLUS,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L3,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L3PLUS,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L4,
            AuthenticatorStatusInterface::FIDO_CERTIFIED_L5,
        ];
    }
}
