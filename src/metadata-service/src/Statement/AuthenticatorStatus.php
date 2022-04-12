<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

abstract class AuthenticatorStatus
{
    final public const NOT_FIDO_CERTIFIED = 'NOT_FIDO_CERTIFIED';

    final public const FIDO_CERTIFIED = 'FIDO_CERTIFIED';

    final public const USER_VERIFICATION_BYPASS = 'USER_VERIFICATION_BYPASS';

    final public const ATTESTATION_KEY_COMPROMISE = 'ATTESTATION_KEY_COMPROMISE';

    final public const USER_KEY_REMOTE_COMPROMISE = 'USER_KEY_REMOTE_COMPROMISE';

    final public const USER_KEY_PHYSICAL_COMPROMISE = 'USER_KEY_PHYSICAL_COMPROMISE';

    final public const UPDATE_AVAILABLE = 'UPDATE_AVAILABLE';

    final public const REVOKED = 'REVOKED';

    final public const SELF_ASSERTION_SUBMITTED = 'SELF_ASSERTION_SUBMITTED';

    final public const FIDO_CERTIFIED_L1 = 'FIDO_CERTIFIED_L1';

    final public const FIDO_CERTIFIED_L1plus = 'FIDO_CERTIFIED_L1plus';

    final public const FIDO_CERTIFIED_L2 = 'FIDO_CERTIFIED_L2';

    final public const FIDO_CERTIFIED_L2plus = 'FIDO_CERTIFIED_L2plus';

    final public const FIDO_CERTIFIED_L3 = 'FIDO_CERTIFIED_L3';

    final public const FIDO_CERTIFIED_L3plus = 'FIDO_CERTIFIED_L3plus';

    final public const FIDO_CERTIFIED_L4 = 'FIDO_CERTIFIED_L4';

    final public const FIDO_CERTIFIED_L5 = 'FIDO_CERTIFIED_L5';

    /**
     * @return string[]
     */
    public static function list(): array
    {
        return [
            self::NOT_FIDO_CERTIFIED,
            self::FIDO_CERTIFIED,
            self::USER_VERIFICATION_BYPASS,
            self::ATTESTATION_KEY_COMPROMISE,
            self::USER_KEY_REMOTE_COMPROMISE,
            self::USER_KEY_PHYSICAL_COMPROMISE,
            self::UPDATE_AVAILABLE,
            self::REVOKED,
            self::SELF_ASSERTION_SUBMITTED,
            self::FIDO_CERTIFIED_L1,
            self::FIDO_CERTIFIED_L1plus,
            self::FIDO_CERTIFIED_L2,
            self::FIDO_CERTIFIED_L2plus,
            self::FIDO_CERTIFIED_L3,
            self::FIDO_CERTIFIED_L3plus,
            self::FIDO_CERTIFIED_L4,
            self::FIDO_CERTIFIED_L5,
        ];
    }
}
