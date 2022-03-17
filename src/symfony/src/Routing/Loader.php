<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Routing;

use Symfony\Component\Config\Loader\Loader as SymfonyLoader;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

class Loader extends SymfonyLoader
{
    private RouteCollection $routes;

    public function __construct()
    {
        parent::__construct();
        $this->routes = new RouteCollection();
    }

    public function add(string $pattern, ?string $host, string $name): void
    {
        $controllerId = sprintf('%s', $name);
        $defaults = [
            '_controller' => $controllerId,
        ];
        $route = new Route($pattern, $defaults, [], [], $host, [], [Request::METHOD_POST]);
        $this->routes->add($name, $route);
    }

    public function load(mixed $resource, string $type = null): RouteCollection
    {
        return $this->routes;
    }

    public function supports(mixed $resource, string $type = null): bool
    {
        return $type === 'webauthn';
    }
}
