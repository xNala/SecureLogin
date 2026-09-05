<?php

spl_autoload_register(function (string $class): void {
    $prefix = 'Library\\';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));

    $file = __DIR__ . '/' . str_replace('\\', '/', $relativeClass) . '.php';

    if (is_file($file) === true) {
        require_once $file;
    }
});
