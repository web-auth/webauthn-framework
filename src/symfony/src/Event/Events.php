<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Event;

abstract class Events
{
    public const WEBAUTHN_PUBLIC_KEY_CREDENTIAL_CREATION_OPTIONS_CREATED = 'webauthn_public_key_credential_creation_options_created';
    public const WEBAUTHN_ATTESTATION_RESPONSE_VALIDATION_FAILED = '';
    public const WEBAUTHN_ATTESTATION_RESPONSE_VALIDATION_SUCCEEDED = '';

    public const WEBAUTHN_PUBLIC_KEY_CREDENTIAL_REQUEST_OPTIONS_CREATED = 'webauthn_public_key_credential_request_options_created';
    public const WEBAUTHN_ASSERTION_RESPONSE_VALIDATION_FAILED = '';
    public const WEBAUTHN_ASSERTION_RESPONSE_VALIDATION_SUCCEEDED = '';
}
