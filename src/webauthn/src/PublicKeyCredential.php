<?php

declare(strict_types=1);

namespace Webauthn;

use Stringable;
use const JSON_THROW_ON_ERROR;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredential extends Credential implements Stringable
{
    public function __construct(
        string $id,
        string $type,
        public readonly string $rawId,
        public readonly AuthenticatorResponse $response
    ) {
        parent::__construct($id, $type);
    }

    public function __toString(): string
    {
        return json_encode($this, JSON_THROW_ON_ERROR);
    }

    public static function create(string $id, string $type, string $rawId, AuthenticatorResponse $response): self
    {
        return new self($id, $type, $rawId, $response);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getRawId(): string
    {
        return $this->rawId;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getResponse(): AuthenticatorResponse
    {
        return $this->response;
    }

    /**
     * @param string[] $transport
     */
    public function getPublicKeyCredentialDescriptor(array $transport = []): PublicKeyCredentialDescriptor
    {
        return PublicKeyCredentialDescriptor::create($this->type, $this->rawId, $transport);
    }
}
