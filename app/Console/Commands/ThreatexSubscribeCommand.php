<?php
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Carbon\Carbon;
use Log;
use DB;

/**
 * Class ThreatexSync
 *
 * @category Console_Command
 * @package  App\Console\Commands
 */
class ThreatexSubscribeCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = "threatex:subscribe
      ";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Register for FBTI Subscriptions";

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
     * Create a new command instance.
     */
    public function __construct()
    {
        parent::__construct();

        $this->application_id = env('TI_APPLICATION_ID');
        $this->application_token = env('TI_APPLICATION_TOKEN');
        $this->api_version = env('TI_API_VERSION');
        $this->api_url = env('TI_API_URL');
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $subscriptions = [
            'malware_analyses',
            'malware_families',
            'threat_descriptors',
            'threat_indicators',
            'threat_tags_descriptors',
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

        $results = json_decode($this->doApiRequest($url), true);

        $this->info("Data for {$method} has been synced");

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
        curl_close($curl);

        return $result;
    }
}
