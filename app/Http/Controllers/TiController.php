<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Elasticsearch\ClientBuilder;
use Webpatser\Uuid\Uuid;
use Log;

class TiController extends Controller
{

    /**
     * The verification token for Facebook
     *
     * @var string
     */
    protected $notify_token;

    /**
     * The Application ID at Facebook
     *
     * @var string
     */
    protected $application_id;

    /**
     * The authentication token for the Application at Facebook
     *
     * @var string
     */
    protected $application_token;

    /**
     * The job error flag, for error detection and handling
     *
     * @var string
     */
    protected $job_error = false;

    /**
     * The job ID, for log prefixing
     *
     * @var string
     */
    protected $job_id = false;

    public function __construct()
    {
        $this->notify_token = env('TI_NOTIFY_TOKEN');
        $this->application_id = env('TI_APPLICATION_ID');
        $this->application_token = env('TI_APPLICATION_TOKEN');
        $this->job_id = Uuid::generate(4);
    }

    /**
     * Verify the token from Facebook Ti.
     *
     * @param  Request $request
     * @return \Illuminate\Http\Response|\Laravel\Lumen\Http\ResponseFactory
     */
    public function verify_token(Request $request)
    {
        $mode = $request->get('hub_mode');
        $token = $request->get('hub_verify_token');

        if ($mode === "subscribe" && $this->notify_token and $token === $this->notify_token) {
            return response($request->get('hub_challenge'));
        }

        return response("Invalid token!", 400);
    }

    /**
     * Handle the query sent to the handler.
     *
     * @param Request $request
     * @return \Illuminate\Http\Response|\Laravel\Lumen\Http\ResponseFactory
     */
    public function handle_query(Request $request)
    {
        $webhook_data = $request->all();

        if (env('APP_DEBUG')) {
            $this->LogInfo("Received the following data package: " . json_encode($webhook_data, true));
        }

        foreach ($webhook_data as $element => $data) {
            switch ($element) {
                case 'entry':
                    $this->handleEntries($data);
                    break;

                case 'object':
                    break;

                case 'q':
                    //just ignore this, q contains the request URI with nginx (not apache for some reason)
                    break;

                default:
                    $this->logError("Received an invalid webhook request {$element}, ignoring request");
            }
        }

        if ($this->job_error) {
            $this->logError("An error has occurred while receiving the following data package: " . json_encode($webhook_data, true));
        }

        //{"success":true}
        return response('ok', 200);
    }

    protected function handleEntries($entries)
    {
        foreach ($entries as $entryId => $entryData) {
            foreach ($entryData as $updateType => $updateData) {
                switch ($updateType) {
                    case 'changes':
                        $this->handleEntryChanges($updateData);
                        break;
                    case 'id':
                        break;
                    case 'time':
                        break;
                    default:
                        return $this->logError("Received an invalid message, ignoring message");
                }
            }
        }

        return true;
    }

    protected function handleEntryChanges($changes)
    {
        $allowed_fields = [
            'malware_analyses',
            'malware_families',
            'threat_descriptors',
            'threat_indicators',
            'threat_tags_descriptors',
        ];

        foreach ($changes as $changeIndex => $changeData) {
            if (!in_array($changeData['field'], $allowed_fields)) {
                return $this->logError("Received an invalid entry change message, ignoring message");
            }

            $index 	= $changeData['field'];
            $type 	= $changeData['field'];
            $id		= $changeData['value']['id'];
            $report 	= $changeData['value'];

            $client = ClientBuilder::create()
                    ->setHosts(config('database.connections.elasticsearch.hosts'))
                    ->build();


            $params = ['index'   => $index];
            if (!$client->indices()->exists($params)) {
                $params['body'] = [
                    'settings' => [
                        'number_of_replicas' => 2
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

            // No document found, so we create one
            if ($search['hits']['total'] === 0) {
                $params = [
                    'index' => $index,
                    'type'  => $type,
                    'id'    => $id,
                    'body'  => $report,
                ];
                $response = $client->index($params);

            // Document found, so we upsert it
            } else {
                $params = [
                    'index' => $index,
                    'type'  => $type,
                    'id'    => $id,
                    'body'  => [
                        'doc' => $report,
                        'upsert'=> 1,//['pkp-report' => 1],
                    ],
                ];
                $response = $client->update($params);
            }

            $this->logInfo(
                "TI-REPORT saved into database : " . json_encode($response)
            );

        }

        return true;
    }

    protected function logError($message)
    {
        Log::error('JOB: ' . $this->job_id . ' WEBHOOK ' . $message);

        $this->job_error = true;

        return false;
    }

    protected function logInfo($message)
    {
        Log::info('JOB: ' . $this->job_id . ' WEBHOOK ' . $message);

        return true;
    }
}
