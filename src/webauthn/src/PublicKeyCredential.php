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

namespace Webauthn;

use JetBrains\PhpStorm\Pure;
use function Safe\json_encode;
use Stringable;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredential extends Credential implements Stringable
{
    #[Pure]
    public function __construct(string $id, string $type, protected string $rawId, protected AuthenticatorResponse $response)
    {
        parent::__construct($id, $type);
    }

    public function __toString(): string
    {
        return json_encode($this);
    }

    #[Pure]
    public function getRawId(): string
    {
        return $this->rawId;
    }

    #[Pure]
    public function getResponse(): AuthenticatorResponse
    {
        return $this->response;
    }

    /**
     * @param string[] $transport
     */
    #[Pure]
    public function getPublicKeyCredentialDescriptor(array $transport = []): PublicKeyCredentialDescriptor
    {
        return PublicKeyCredentialDescriptor::create($this->getType(), $this->getRawId(), $transport);
    }
}
