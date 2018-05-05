<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Log;

class CspController extends Controller {
    public function __construct()
    {
        //
    }

    public function report(Request $request) {
        $csp_data = json_decode($request->getContent(), true);

$hosts = explode(',', env('ES_HOSTS'));

$client = ClientBuilder::create()
                    ->setHosts($hosts)
                    ->build();

$params = [
    'index' => 'my_index',
    'type' => 'my_type',
    'id' => 'my_id',
    'body' => [
        'script' => [
            'source' => 'ctx._source.counter += params.count',
            'params' => [
                'count' => 4
            ],
        ],
        'upsert' => [
            'counter' => 1
        ],
    ]
];

$response = $client->update($params);

/*
        $collection = (new MongoDB\Client)->fbti->csp_reports;
        $insertResult = $collection->insertOne($csp_data);

        Log::info(
            "CSP-REPORT saved into database under ID : {$insertResult->getInsertedId()}" . json_encode($csp_data,true)
        );
*/

        return response('', 200);
    }
}
