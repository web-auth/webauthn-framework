<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use Assert\Assertion;
use Base64Url\Base64Url;
use InvalidArgumentException;
use JetBrains\PhpStorm\Pure;
use function Safe\json_decode;
use function Safe\sprintf;
use Webauthn\TokenBinding\TokenBinding;

class CollectedClientData
{
    private array $data;

    private string $type;

    private string $challenge;

    private string $origin;

    private ?array $tokenBinding;

    public function __construct(private string $rawData, array $data)
    {
        $this->type = $this->findData($data, 'type');
        $this->challenge = $this->findData($data, 'challenge', true, true);
        $this->origin = $this->findData($data, 'origin');
        $this->tokenBinding = $this->findData($data, 'tokenBinding', false);
        $this->data = $data;
    }

    public static function createFormJson(string $data): self
    {
        $rawData = Base64Url::decode($data);
        $json = json_decode($rawData, true);
        Assertion::isArray($json, 'Invalid collected client data');

        return new self($rawData, $json);
    }

    #[Pure]
    public function getType(): string
    {
        return $this->type;
    }

    #[Pure]
    public function getChallenge(): string
    {
        return $this->challenge;
    }

    #[Pure]
    public function getOrigin(): string
    {
        return $this->origin;
    }

    public function getTokenBinding(): ?TokenBinding
    {
        return null === $this->tokenBinding ? null : TokenBinding::createFormArray($this->tokenBinding);
    }

    #[Pure]
    public function getRawData(): string
    {
        return $this->rawData;
    }

    /**
     * @return string[]
     */
    #[Pure]
    public function all(): array
    {
        return array_keys($this->data);
    }

    #[Pure]
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function get(string $key): mixed
    {
        if (!$this->has($key)) {
            throw new InvalidArgumentException(sprintf('The key "%s" is missing', $key));
        }

        return $this->data[$key];
    }

    private function findData(array $json, string $key, bool $isRequired = true, bool $isB64 = false): mixed
    {
        if (!array_key_exists($key, $json)) {
            if ($isRequired) {
                throw new InvalidArgumentException(sprintf('The key "%s" is missing', $key));
            }

            return null;
        }

        return $isB64 ? Base64Url::decode($json[$key]) : $json[$key];
    }
}
