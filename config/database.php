<?php

return [

    'fetch' => PDO::FETCH_CLASS,

    'default' => env('DB_DRIVER', 'mongodb'),

    'connections' => [

        'mysql' => [
            'driver'    => 'mysql',
            'host'      => env('DB_HOST', 'localhost'),
            'port'      => env('DB_PORT', 3306),
            'database'  => env('DB_DATABASE', 'aite'),
            'username'  => env('DB_USERNAME', 'root'),
            'password'  => env('DB_PASSWORD', ''),
            'charset'   => 'utf8',
            'collation' => 'utf8_unicode_ci',
            'prefix'    => '',
            'strict'    => false,
        ],

        'mongodb' => [
            'driver'    => 'mongodb',
            'host'      => env('MB_HOST', 'localhost'),
            // When using replica:
            //'host'     => ['server1', 'server2'],
            'port'      => env('MB_PORT', 27017),
            'database'  => env('MB_DATABASE', 'aite'),
            'username'  => env('MB_USERNAME', 'root'),
            'password'  => env('MB_PASSWORD', ''),
            'options'  => [
                // When using replica
                // 'replicaSet' => 'replicaSetName'
                'database' => 'admin' // sets the authentication database required by mongo 3
            ]
        ],
    ],

    'migrations' => 'migrations',

];