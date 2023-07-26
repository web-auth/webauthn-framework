<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizableInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\Exception\AuthenticationExtensionException;

final class ExtensionManager
{

    /**
     * @var array<string, Extension>
     */
    private array $extensions = [];

    public static function create(): self
    {
        return new self();
    }

    public function add(Extension $extension): void
    {
        $this->extensions[$extension::identifier()] = $extension;
    }

    public function loadFromOutput(array $data): ExtensionOutputs
    {
        $extensionOutputs = ExtensionOutputs::create();
        foreach ($data as $identifier => $value) {
            is_string($identifier) || throw new AuthenticationExtensionException('Invalid extension key');
            if (isset($this->extensions[$identifier])) {
                $extension = $this->extensions[$identifier]::loadOutput($value);
            } else {
                $extension = GenericExtension::create($identifier, $value);
            }
            $extensionOutputs->add($extension);
        }

        return $extensionOutputs;
    }

    public function loadFromInput(array $data): ExtensionInputs
    {
        $extensionInputs = ExtensionInputs::create();
        foreach ($data as $identifier => $value) {
            is_string($identifier) || throw new AuthenticationExtensionException('Invalid extension key');
            if (isset($this->extensions[$identifier])) {
                $extension = $this->extensions[$identifier]::loadInput($value);
            } else {
                $extension = GenericExtension::create($identifier, $value);
            }
            $extensionInputs->add($extension);
        }

        return $extensionInputs;
    }

    public function check(ExtensionInputs $inputs, ExtensionOutputs $outputs): void
    {
        foreach ($this->extensions as $extension) {
            if (!$inputs->has($extension::identifier())) {
                continue;
            }
            $input = $inputs->get($extension::identifier());
            $output = $outputs->has($extension::identifier()) ? $outputs->get($extension::identifier()) : null;
            $extension->check($input, $output);
        }
    }
}
