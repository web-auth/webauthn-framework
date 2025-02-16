<?php

declare(strict_types=1);

namespace Webauthn;

abstract class PublicKeyCredentialEntity
{
    /**
     * @deprecated since 5.1.0 and will be removed in 6.0.0. This value is always null.
     */
    public ?string $icon = null;

    public function __construct(
        public readonly string $name,
        ?string $icon = null
    ) {
        if ($icon !== null) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.1.0',
                'The parameter "$icon" is deprecated since 5.1.0 and will be removed in 6.0.0. This value has no effect. Please set "null" instead.'
            );
        }
    }
}
