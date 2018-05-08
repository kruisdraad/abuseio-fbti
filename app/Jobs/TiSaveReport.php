<?php

namespace App\Jobs;

use Elasticsearch\ClientBuilder;
use Exception;
use Log;

class TiSaveReport extends Job// implements SelfHandling
{
    /**
     * @var array
     */
    private $data;

    /**
     * The Application ID at Facebook
     *
     * @var string
     */
    private $application_id;

    /**
     * The authentication token for the Application at Facebook
     *
     * @var string
     */
    private $application_token;

    /**
     * The job error flag, for error detection and handling
     *
     * @var string
     */
    private $job_error = false;

    /**
     * @var string
     */
    private $job_id;

    /**
     * @var boolean
     */
    private $debug;

    /**
     * Create a new job instance.
     *
     * @param array $data
     * @throws Exception
     * @return void
     */
    public function __construct($id, $data)
    {
        $this->data = $data;
        $this->job_id = $id;

        $this->application_id = env('TI_APPLICATION_ID');
        $this->application_token = env('TI_APPLICATION_TOKEN');
        $this->debug = env('APP_DEBUG');
    }

    /**
     * Execute the job.
     *
     */
    public function handle()
    {
        $this->logInfo('Job is starting');

        if ($this->debug) {
            $this->LogInfo("Data package: " . json_encode($this->data, true));
        }

        foreach ($this->data as $element => $data) {
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
            $this->logError("An error has occurred while receiving the following data package: " . json_encode($this->data));
            return false;
        }

        return true;
    }

    /**
     * Handle each entry.
     *
     * @param array $entries
     * @return boolean
     */
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

    /**
     * Handle each change.
     *
     * @param array $changes
     * @return boolean
     */
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

            // Check if index exists or create it
            $params = ['index'   => $index];
            if (!$client->indices()->exists($params)) {
                $params['body'] = [
                    'settings' => [
                        'number_of_replicas' => config('database.connections.elasticsearch.replicas'),
                    ],
                ];
                $response = $client->indices()->create($params);

                $this->logInfo(
                    "Index for {$index} did not exist and was created with replicas: " .
                    config('database.connections.elasticsearch.replicas') .
                    json_encode($response)
                );
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
            $current_report = $search['hits']['hits'][0]['_source'];

            // No document found, so we create one
            if ($search['hits']['total'] === 0) {
                $params = [
                    'index' => $index,
                    'type'  => $type,
                    'id'    => $id,
                    'body'  => $report,
                ];
                $response = $client->index($params);

                $this->logInfo(
                    "TI-REPORT saved into database : " . json_encode($response)
                );

            // Document found, but is an exact match, so we ignore it (testing)
            } elseif ($current_report === $report) {
                $this->logInfo(
                    "TI-REPORT ignored as it would result in expensive ES-NOOP in {$index}/{$type}/{$id}"
                );

            // Document found and diffs, so we upsert it 
            } else {

                $params = [
                    'index' => $index,
                    'type'  => $type,
                    'id'    => $id,
                    'body'  => [
                        'doc' => $report,
                        'upsert'=> 1,
                    ],
                    'retry_on_conflict' => 5,
                ];
                $response = $client->update($params);

                $this->logInfo(
                    "TI-REPORT saved into database : " . json_encode($response)
                );
            }

        }

        return true;
    }

    /**
     * Handle log error.
     *
     * @param string $message
     * @return boolean
     */
    protected function logError($message)
    {
        Log::error('JOB: ' . $this->job_id . ' : ' . $message);

        $this->job_error = true;

        return false;
    }

    /**
     * Handle info error.
     *
     * @param string $message
     * @return boolean
     */
    protected function logInfo($message)
    {
        Log::info('JOB: ' . $this->job_id . ' : ' . $message);

        return true;
    }
}
