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
     * The verify token for local Application
     *
     * @var string
     */
    protected $verify_token;

    /**
     * The url for local Application
     *
     * @var string
     */
    protected $app_url;


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
        $this->verify_token = env('TI_NOTIFY_TOKEN');
        $this->api_version = env('TI_API_VERSION');
        $this->api_url = env('TI_API_URL');
        $this->app_url = env('APP_URL');
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

        // Do the first request
        $url = "{$this->api_url}/{$this->api_version}/{$this->application_id}/subscriptions?access_token={$this->application_id}|{$this->application_token}&";

        $fields = [];
        foreach($subscriptions as $subscription) {
            $fields[] = $subscription;
        }

        $parameters = [
            'object' => 'threat_exchange',
            'callback_url' => $this->app_url .'/get_report',
            'verify_token' => $this->verify_token,
            'fields' => $fields,
        ];

        $results = json_decode($this->doApiPostRequest($url, $parameters), true);

        if($results['success'] === true){
            $this->info("Sucessfully registered for subscriptions");
        } else {
            $this->error("Could not register TODO:add reason");
        }

        return true;
    }

    protected function doApiPostRequest($url, $parameters)
    {
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($parameters),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        ]);

        $result = curl_exec($curl);
        curl_close($curl);

        return $result;
    }
}
