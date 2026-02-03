<?php

declare(strict_types=1);

namespace Webauthn;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 *
 * @deprecated since 5.3, use CredentialRecord instead. Will be removed in 6.0.
 */
class PublicKeyCredentialSource extends CredentialRecord
{
}
