<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use function array_key_exists;
use Assert\Assertion;
use function Safe\sprintf;

class PatternAccuracyDescriptor extends AbstractDescriptor
{
    private int $minComplexity;

    public function __construct(int $minComplexity, ?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        Assertion::greaterOrEqualThan($minComplexity, 0, Utils::logicException('Invalid data. The value of "minComplexity" must be a positive integer'));
        $this->minComplexity = $minComplexity;
        parent::__construct($maxRetries, $blockSlowdown);
    }

    
    public function getMinComplexity(): int
    {
        return $this->minComplexity;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        Assertion::keyExists($data, 'minComplexity', Utils::logicException('The key "minComplexity" is missing'));
        foreach (['minComplexity', 'maxRetries', 'blockSlowdown'] as $key) {
            if (array_key_exists($key, $data)) {
                Assertion::integer($data[$key], Utils::logicException(sprintf('Invalid data. The value of "%s" must be a positive integer', $key)));
            }
        }

        return new self(
            $data['minComplexity'],
        $data['maxRetries'] ?? null,
        $data['blockSlowdown'] ?? null
        );
    }

    
    public function jsonSerialize(): array
    {
        $data = [
            'minComplexity' => $this->minComplexity,
            'maxRetries' => $this->getMaxRetries(),
            'blockSlowdown' => $this->getBlockSlowdown(),
        ];

        return Utils::filterNullValues($data);
    }
}
