<?php
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Elasticsearch\ClientBuilder;
use Webpatser\Uuid\Uuid;
use Exception;
use Carbon\Carbon;
use Log;

/**
 * Class ThreatexSync
 *
 * @category Console_Command
 * @package  App\Console\Commands
 */
class ThreatexSyncCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = "threatex:sync 
      {--threat_exchange_members : Sync exchange members} 
      {--malware_analyses : Sync malware analysis}
      {--malware_families : Sync malware families}
      {--threat_descriptors : Sync threat descriptors} 
      {--threat_indicators : Sync threat indicators}
      {--since=48 hours ago : Starting date of data to be collected}
      {--until=now : Ending date of data to be collected}
      {--limit=1000 : Amount between 1 and 1000 of entries to be collected in a single API call}
      ";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Sync data from FBTI";

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
     * The version of API for the Application at Facebook
     *
     * @var string
     */
    protected $api_version;

    /**
     * The URL of API for the Application at Facebook
     *
     * @var string
     */
    protected $api_url;

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

    /**
     * Create a new command instance.
     */
    public function __construct()
    {
        parent::__construct();

        $this->application_id = env('TI_APPLICATION_ID');
        $this->application_token = env('TI_APPLICATION_TOKEN');
        $this->api_version = env('TI_API_VERSION');
        $this->api_url = env('TI_API_URL');
        $this->job_id = Uuid::generate(4);

    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        try {
            if ($this->option('malware_analyses')) {
                $this->doSyncRequest('malware_analyses');
            }

            if ($this->option('malware_families')) {
                $this->doSyncRequest('malware_families');
            }

            if ($this->option('threat_descriptors')) {
                $this->doSyncRequest('threat_descriptors');
            }

            if ($this->option('threat_indicators')) {
                $this->doSyncRequest('threat_indicators');
            }

            if ($this->option('threat_exchange_members')) {
                $this->doSyncRequest('threat_exchange_members');
            }

        } catch (Exception $e) {
            $this->logError("An error occurred" . $e->getMessage() . PHP_EOL);
            return false;
        }

        return true;
    }

    protected function doSyncRequest($method) {
        $allowed_methods = [
            'malware_analyses',
            'malware_families',
            'threat_descriptors',
            'threat_indicators',
            'threat_exchange_members',
        ];

        if (!in_array($method, $allowed_methods)) {
            return false;
        }

        // Do the first request
        $base_url = "{$this->api_url}/{$this->api_version}/{$method}?access_token={$this->application_id}|{$this->application_token}&";

        $parameters = [
            'since'             => Carbon::parse($this->option('since'))->timestamp,
            'until'             => Carbon::parse($this->option('until'))->timestamp,
            'limit'             => $this->option('limit'),
            'include_expired'   => 'true',
            'sort_by'           => 'CREATE_TIME',
            'sort_order'        => 'ASCENDING',
        ];

        $url = $base_url . http_build_query($parameters);
        while($url != false) {
            //echo "URL $url" . PHP_EOL;

            $results = json_decode($this->doApiRequest($url), true);

            $this->saveResults($method, $results);

            if (!empty($results['paging']['cursors']['after'])) {
                $parameters['after'] = $results['paging']['cursors']['after'];
                $url = $base_url . http_build_query($parameters);
            } else {
                $url = false;
            }
        }

        $this->logInfo("Data for {$method} has been synced");

        return true;
    }

    protected function saveResults($method, $results) {
        $last = end($results['data']);
        echo 'URL last id : ' . $last['id'] . PHP_EOL;

        foreach($results['data'] as $values) {
            $index 	= $method;
            $type 	= $method;
            $id		= $values['id'];
            $report = $values;

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
        }

        return true;
    }

    protected function doApiRequest($url)
    {
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_TIMEOUT => 30000,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "GET",
        ]);

        $result = curl_exec($curl);
        //TODO error handling
        //$err = curl_error($curl);
        //echo "cURL Error #:" . $err;
        curl_close($curl);

        return $result;
    }

    protected function logError($message) {
        $this->error($message);
        Log::error("CONSOLE {$this->getName()} {$message}");
    }

    protected function logInfo($message) {
        $this->info($message);
        Log::info("CONSOLE {$this->getName()} {$message}");
    }
}
