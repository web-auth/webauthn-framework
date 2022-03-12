<?php

declare(strict_types=1);

namespace Webauthn;

use function Safe\json_encode;
use Stringable;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredential extends Credential implements Stringable
{
    
    public function __construct(string $id, string $type, protected string $rawId, protected AuthenticatorResponse $response)
    {
        parent::__construct($id, $type);
    }

    public function __toString(): string
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
        return PublicKeyCredentialDescriptor::create($this->getType(), $this->getRawId(), $transport);
    }
}
