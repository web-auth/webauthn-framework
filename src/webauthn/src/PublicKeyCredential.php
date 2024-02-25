<?php

declare(strict_types=1);

namespace Webauthn;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredential extends Credential
{
    public function __construct(
        string $id,
        string $type,
        public readonly string $rawId,
        public readonly AuthenticatorResponse $response
    ) {
        parent::__construct($id, $type);
    }

    public static function create(string $id, string $type, string $rawId, AuthenticatorResponse $response): self
    {
        return new self($id, $type, $rawId, $response);
    }

    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        $transport = $this->response instanceof AuthenticatorAttestationResponse ? $this->response->transports : [];

        return PublicKeyCredentialDescriptor::create($this->type, $this->rawId, $transport);
    }
}
