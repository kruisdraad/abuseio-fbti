<?php
namespace App\Console\Commands;

use Elasticsearch\ClientBuilder;
use Illuminate\Console\Command;
use Pheanstalk\Pheanstalk;
use Exception;
use Log;

/**
 * Class ThreatexSync
 *
 * @category Console_Command
 * @package  App\Console\Commands
 */
class WorkerEnrichCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = "worker:enrich
      ";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Fires off jobs to enrich data";

    protected $fields = [
            'threat_descriptors',
        ];


    /**
     * Create a new command instance.
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     * @throws
     */
    public function handle()
    {
        foreach($this->fields as $field) {
            $this->$field();
        }
    }

    private function threat_descriptors($index='threat_descriptors', $type='threat_descriptors') {

            $client = ClientBuilder::create()
                ->setHosts(config('database.connections.elasticsearch.hosts'))
                ->build();

            // Check for existing record
            $params = [
                'index' => $index,
                'type'  => $type,
                'size' => 50,
                'body' => [
                    'query' => [
                        'bool' => [
                            'must_not' => [
                                'exists' => [
                                    'field' => 'enriched',
                                 ]
                            ]
                        ]
                    ] 
                ]
            ];
            $search = $client->search($params);

            foreach($search['hits']['hits'] as $found) {
                //var_dump($found);
            }

    }
}

