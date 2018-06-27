<?php

namespace App\Jobs;

use Elasticsearch\ClientBuilder;
use Pheanstalk\Pheanstalk;
use Exception;
use Log;

class TiSaveReport extends Job
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
            'threat_exchange_members',
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

            $current_report = [];
            if(!empty($search['hits']['hits'][0])) {
                if(!empty($search['hits']['hits'][0]['_source']) && is_array($search['hits']['hits'][0]['_source'])) {
                    $current_report = $search['hits']['hits'][0]['_source'];
                }
            }
            // Remove locally enriched data
            if(!empty($current_report['enrichments'])) {
                unset($current_report['enrichments']);
            }

            // No document found, so we create one
            if ($search['hits']['total'] === 0) {
                if ($index == 'threat_descriptors') {
                    $report['enrichments'] = $this->enrichments($report);
                }

                $params = [
                    'index' => $index,
                    'type'  => $type,
                    'id'    => $id,
                    'body'  => $report,
                ];
                $response = $client->index($params);

                $this->logInfo(
                    "TI-REPORT created into database : " . json_encode($response)
                );
                if ($index == 'threat_descriptors') {
                    $this->notifications($report);
                }

            // Document found, but is an exact match, so we ignore it (testing)
            } elseif (!$this->changesBetween($report, $current_report)) {
                $this->logInfo(
                    "TI-REPORT ignored as it would result in expensive ES-NOOP in {$index}/{$type}/{$id}"
                );

            // Document found and diffs, so we upsert it 
            } else {
                if ($index == 'threat_descriptors') {
                    $report['enrichments'] = $this->enrichments($report);
                }

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

                if($response['result'] == 'noop') {
                    $this->logInfo(
                        "TI-REPORT Detected NOOP while expected UPDATE or CREATED response. Document matching must have failed, which gives extra load to Elasticsearch!" .
                        " compare 1 : " . json_encode($this->compare($current_report, $report)) .
                        " compare 2 : " . json_encode($this->compare($report, $current_report))
                    );
                }

                $this->logInfo(
                    "TI-REPORT saved into database : " . json_encode($response)
                );

                if ($index == 'threat_descriptors') {
                    $this->notifications($report);
                }
            }
        }

        return true;
    }

    /**
     * Checks weither notifications are required for the object based on walking thru a set
     * of rules to match. These rules should be stored in ES in the near feature, for now
     * its an hardcoded json object outside the public source code.
     *
     * @param array $report
     * @return boolean
     */
    private function notifications($report) {
        $this->logInfo(
            "Notifcations method has been called"
        );

        return true;
    }

    /**
     * Returns an array with enrichment values, lookup based on external sources e.g. Cymru
     * This hook is always called and will descide on its own if it should return any data.
     *
     * @param string EnrichmentType
     * @param array EnrichmentValue
     * @return array
     */
    private function enrichments($report) {
        $this->logInfo(
            "Enrichment method has been called"
        );

        $enrichments = [];

        $value = $report['indicator']['indicator'];
        $type = $report['indicator']['type'];

        switch ($type) {

            case 'URI':
                $enrichments = $this->enrichUri($value);
                break;

            case 'DOMAIN':
                $enrichments = $this->enrichDomain($value);
                break;

            case 'IP_ADDRESS':
                $enrichments = $this->enrichAddress($value);
                break;

            case 'IP_SUBNET':
                $enrichments = $this->enrichSubnet($value);
                break;

            case 'AS_NUMBER':
                $enrichments = $this->enrichAsn($value);
                break;

            case 'EMAIL_ADDRESS':
                $enrichments = $this->enrichEmail($value);
                break;

            default:
                return [];
        }

        if (is_array($enrichments)) {
            return $enrichments;
        } else {
            return [];
        }
    }

    private function enrichUri($value) {
    }

    private function enrichDomain($value) {
    }

    private function enrichAddress($value) {
        $zone4 = 'origin.asn.cymru.com';
        $zone6 = 'origin6.asn.cymru.com';

        $enrichment = [];

        if(filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $value); 
            $dnslookup = implode('.', array_reverse($parts)) . ".{$zone4}.";
        }
        if(filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $addr = inet_pton($ip);
            $unpack = unpack('H*hex', $addr);
            $hex = $unpack['hex'];
            $dnslookup = implode('.', array_reverse(str_split($hex))) . ".{$zone6}.";
        }

        $result = dns_get_record($dnslookup, DNS_TXT);
        if(!empty($result[0]['txt'])) {
            // 14061 | 2604:a880:1::/48 | US | arin | 2013-04-11
            $response = $result[0]['txt'];
            $enrichment = array_combine(
                [ 'asn', 'prefix', 'bgpcountry', 'region', 'somedate' ],
                explode(" | ", $response)
            );
        }

        return $enrichment;
    }

    private function enrichSubnet($value) {
        // Not implement as there are no subnet entries yet
    }

    private function enrichAsn($value) {
        // Not implement as there are no subnet entries yet
    }

    private function enrichEmail($value) {
        // Not implement as there are no subnet entries yet
    }

    /**
     * Returns an array with the differences between $array1 and $array2
     *
     * @param array $aArray1
     * @param array $aArray2
     * @return array
     */
    private function changesBetween($array1, $array2) {
        $forward  = $this->compare($array1, $array2);
        $backward = $this->compare($array2, $array1);

        if (!empty($forward)) {
            return true;
        }

        if (!empty($backward)) {
            return true;
        }

        return false;
    }

    public static function compare($array1, $array2)
    {
        $result = array();
        foreach ($array1 as $key => $value) {
            if (!is_array($array2) || !array_key_exists($key, $array2)) {
                $result[$key] = $value;
                continue;
            }
            if (is_array($value)) {
                $recursiveArrayDiff = static::compare($value, $array2[$key]);
                if (count($recursiveArrayDiff)) {
                    $result[$key] = $recursiveArrayDiff;
                }
                continue;
            }
            if ($value != $array2[$key]) {
                $result[$key] = $value;
            }
        }
        return $result;
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
