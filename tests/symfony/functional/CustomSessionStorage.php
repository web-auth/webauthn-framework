<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Assert\Assertion;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;

final class CustomSessionStorage implements OptionsStorage
{
    private null|Item $item = null;

    public function store(Item $item): void
    {
        $this->item = $item;
    }

    public function get(): Item
    {
        Assertion::notNull($this->item, 'No public key credential options available for this session.');

        return $this->item;
    }
}
