<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function is_array;
use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;

/**
 * @final
 */
class VerificationMethodANDCombinations implements JsonSerializable
{
    /**
     * @var VerificationMethodDescriptor[]
     */
    private array $verificationMethods = [];

    public function addVerificationMethodDescriptor(VerificationMethodDescriptor $verificationMethodDescriptor): self
    {
        $this->verificationMethods[] = $verificationMethodDescriptor;

        return $this;
    }

    /**
     * @return VerificationMethodDescriptor[]
     */
    public function getVerificationMethods(): array
    {
        return $this->verificationMethods;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $object = new self();

        foreach ($data as $datum) {
            is_array($datum) || throw MetadataStatementLoadingException::create('Invalid data');
            $object->addVerificationMethodDescriptor(VerificationMethodDescriptor::createFromArray($datum));
        }

        return $object;
    }

    /**
     * @return array<array<mixed>>
     */
    public function jsonSerialize(): array
    {
        return array_map(
            static fn (VerificationMethodDescriptor $object): array => $object->jsonSerialize(),
            $this->verificationMethods
        );
    }
}
