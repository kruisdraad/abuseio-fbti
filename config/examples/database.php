<?php
$es_hosts = ['http://localhost:9200'];

// Dont touch this
if (!empty(env('ES_HOSTS'))) {
    $es_hosts = explode(',', env('ES_HOSTS'));
}
// End of dont touch this

return [

    'fetch' => PDO::FETCH_CLASS,

    'default' => env('DB_DRIVER', 'mysql'),

    'connections' => [

        'elasticsearch' => [
            'hosts'     => $es_hosts,
            'replicas'  => env('ES_REPLICAS', '1'),
        ],

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

    ],

    'migrations' => 'migrations',

];
