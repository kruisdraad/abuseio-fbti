<?php
// Dont touch this
if (!empty(env('ES_HOSTS'))) {
    $es_hosts = [];
    $hosts = explode(',', env('ES_HOSTS'));
    foreach($hosts as $host) {
        $es_hosts[] = [
            'host'    => $host,
            'port'    => env('ES_PORT'),
            'scheme'  => 'http',
            'user'    => env('ES_USERNAME'),
            'pass'    => env('ES_PASSWORD'),
        ];
    }
} else {
    $es_hosts = [
        'host' => 'localhost',
        'port' => '9200',
        'schema' => 'http',
    ];
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
