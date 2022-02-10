<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use function Safe\json_encode;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredential extends Credential
{
    /**
     * @var string
     */
    protected $rawId;

    /**
     * @var AuthenticatorResponse
     */
    protected $response;

	/**
	 * @var AuthenticationExtensionsClientOutputs $clientExtensionResults
	 */
	protected $clientExtensionResults;

	public function __construct(string $id, string $type, string $rawId, AuthenticatorResponse $response, AuthenticationExtensionsClientOutputs $clientExtensionResults)
    {
        parent::__construct($id, $type);
        $this->rawId = $rawId;
        $this->response = $response;
		$this->clientExtensionResults = $clientExtensionResults;
    }

    public function __toString()
    {
        return json_encode($this);
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

	public function getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
		return $this->clientExtensionResults;
	}
}
