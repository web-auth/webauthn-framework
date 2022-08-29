<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

interface OptionsStorage
{
    public function store(Item $item): void;

    public function get(/*string|null $challenge = null*/): Item;
}
