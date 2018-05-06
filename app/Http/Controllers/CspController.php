<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Elasticsearch\ClientBuilder;
use Webpatser\Uuid\Uuid;
use Log;

class CspController extends Controller {
    public function __construct()
    {
        //
    }

    public function report(Request $request) {
        $csp_data = json_decode($request->getContent(), true);

        $index = 'csp';
        $type  = 'report';
        $id    =  Uuid::generate(4);

        $client = ClientBuilder::create()
                    ->setHosts(config('database.connections.elasticsearch.hosts'))
                    ->build();

        // Check if index exists or create it
        $params = ['index'   => $index];
        if (!$client->indices()->exists($params)) {
            $params['body'] = [
                'settings' => [
                    'number_of_replicas' => config('database.connections.elasticsearch.replicas'),
                ],
            ];
            $response = $client->indices()->create($params);
        }

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
                'body'  => $csp_data,
            ];
            $response = $client->index($params);

        } else {
            // Document found, so we upsert it

            $params = [
                'index' => $index,
                'type'  => $type,
                'id'    => $id,
                'body'  => [
		    'doc' => $csp_data, 
                    'upsert'=> ['csp-report' => 1],
                ],
            ];
            $response = $client->update($params);
        }

        Log::info(
            "CSP-REPORT saved into database : " . json_encode($response)
        );


        return response('', 200);
    }
}
