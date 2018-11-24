<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredential extends Credential
{
    private $rawId;

    private $response;

    public function __construct(string $id, string $type, string $rawId, AuthenticatorResponse $response)
    {
        parent::__construct($id, $type);
        $this->rawId = $rawId;
        $this->response = $response;
    }

    public function getRawId(): string
    {
        return $this->rawId;
    }

    public function getResponse(): AuthenticatorResponse
    {
        return $this->response;
    }

    /**
     * @param string[] $transport
     */
    public function getPublicKeyCredentialDescriptor(array $transport = []): PublicKeyCredentialDescriptor
    {
        return new PublicKeyCredentialDescriptor($this->getType(), $this->getRawId(), $transport);
    }
}
