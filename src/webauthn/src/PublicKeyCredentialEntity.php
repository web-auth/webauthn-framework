<?php

declare(strict_types=1);

namespace Webauthn;

abstract class PublicKeyCredentialEntity
{
    /**
     * @deprecated since 5.3.0 and will be removed in 6.0.0. Please set "" and use PublicKeyCredentialUserEntity.name instead.
     */
    public string $name;

    /**
     * @deprecated since 5.1.0 and will be removed in 6.0.0. This value is always null.
     */
    public ?string $icon = null;

    public function __construct(string $name, ?string $icon = null)
    {
        if ($name !== '') {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.3.0',
                'The parameter "$name" is deprecated since 5.3.0 and will be removed in 6.0.0. Please set "" and use PublicKeyCredentialUserEntity.name instead.'
            );
        }
        $this->name = $name;

        if ($icon !== null) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.1.0',
                'The parameter "$icon" is deprecated since 5.1.0 and will be removed in 6.0.0. This value has no effect. Please set "null" instead.'
            );
        }
    }
}
