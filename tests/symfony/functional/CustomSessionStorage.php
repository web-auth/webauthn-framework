<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use LogicException;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;

final class CustomSessionStorage implements OptionsStorage
{
    private null|Item $item = null;

    public function store(Item $item): void
    {
        $this->item = $item;
    }

    public function get(string $challenge): Item
    {
        if ($this->item === null) {
            throw new LogicException('No public key credential options available for this session.');
        }

        return $this->item;
    }
}
