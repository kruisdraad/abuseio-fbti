<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Elasticsearch\ClientBuilder;
use Webpatser\Uuid\Uuid;
use Log;

class PkpController extends Controller {
    public function __construct()
    {
        //
    }

    public function report(Request $request) {
        $pkp_data = json_decode($request->getContent(), true);

        $index = 'pkp';
        $type  = 'report';
        $id    =  Uuid::generate(4);

        $client = ClientBuilder::create()
                    ->setHosts(config('database.connections.elasticsearch.hosts'))
                    ->build();

        // Check for existing record
        $params = [
            'index' => $index,
            'type'  => $type,
            'body'  => [
                'query' => [
                    'match' => [
                        'id' => $id
                    ]
                ]
            ]
        ];
        $search = $client->search($params);

        if ($search['hits']['total'] === 0) {
            // No document found, so we create one
            $params = [
                'index' => $index,
                'type'  => $type,
                'id'    => $id,
                'body'  => $pkp_data,
            ];
            $response = $client->index($params);

        } else {
            // Document found, so we upsert it

            $params = [
                'index' => $index,
                'type'  => $type,
                'id'    => $id,
                'body'  => [
                    'doc' => $pkp_data,
                    'upsert'=> ['pkp-report' => 1],
                ],
            ];
            $response = $client->update($params);
        }

        Log::info(
            "PKP-REPORT saved into database : " . json_encode($response)
        );

        return response('', 200);
    }
}
