<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service\Fixture;

use RuntimeException;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;

final class InMemoryOptionsStorage implements OptionsStorage
{
    private ?Item $last = null;

    public function store(Item $item): void
    {
        $this->last = $item;
    }

    public function get(string $challenge): Item
    {
        return $this->last ?? throw new RuntimeException('No item stored.');
    }

    public function last(): Item
    {
        return $this->last ?? throw new RuntimeException('No item stored.');
    }
}
