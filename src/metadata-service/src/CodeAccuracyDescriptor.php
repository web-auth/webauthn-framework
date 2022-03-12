<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;

class CodeAccuracyDescriptor extends AbstractDescriptor
{
    private int $base;

    private int $minLength;

    public function __construct(int $base, int $minLength, ?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        Assertion::greaterOrEqualThan($base, 0, Utils::logicException('Invalid data. The value of "base" must be a positive integer'));
        Assertion::greaterOrEqualThan($minLength, 0, Utils::logicException('Invalid data. The value of "minLength" must be a positive integer'));
        $this->base = $base;
        $this->minLength = $minLength;
        parent::__construct($maxRetries, $blockSlowdown);
    }


    public function getBase(): int
    {
        return $this->base;
    }


    public function getMinLength(): int
    {
        return $this->minLength;
    }

    public static function createFromArray(array $data): self
    {
        Assertion::keyExists($data, 'base', Utils::logicException('The parameter "base" is missing'));
        Assertion::keyExists($data, 'minLength', Utils::logicException('The parameter "minLength" is missing'));

        return new self(
            $data['base'],
            $data['minLength'],
            $data['maxRetries'] ?? null,
            $data['blockSlowdown'] ?? null
        );
    }


    public function jsonSerialize(): array
    {
        $data = [
            'base' => $this->base,
            'minLength' => $this->minLength,
            'maxRetries' => $this->getMaxRetries(),
            'blockSlowdown' => $this->getBlockSlowdown(),
        ];

        return Utils::filterNullValues($data);
    }
}
