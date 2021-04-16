<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Routing;

use JetBrains\PhpStorm\Pure;
use function Safe\sprintf;
use Symfony\Component\Config\Loader\Loader as SymfonyLoader;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

class Loader extends SymfonyLoader
{
    private RouteCollection $routes;

    #[Pure]
    public function __construct()
    {
        $this->routes = new RouteCollection();
    }

    public function add(string $pattern, ?string $host, string $name): void
    {
        $controllerId = sprintf('%s:__invoke', $name);
        $defaults = ['_controller' => $controllerId];
        $route = new Route($pattern, $defaults, [], [], $host, ['https'], [Request::METHOD_POST]);
        $this->routes->add(sprintf('webauthn_%s', $name), $route);
    }

    /**
     * @param mixed       $resource
     * @param string|null $type
     */
    public function load($resource, $type = null): RouteCollection
    {
        return $this->routes;
    }

    /**
     * @param mixed       $resource
     * @param string|null $type
     */
    #[Pure]
    public function supports($resource, $type = null): bool
    {
        return 'webauthn' === $type;
    }
}
