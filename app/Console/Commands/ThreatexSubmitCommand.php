<?php
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Carbon\Carbon;

/**
 * Class ThreatexSync
 *
 * @category Console_Command
 * @package  App\Console\Commands
 */
class ThreatexSubmitCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = "threatex:submit
            {--confidence=          : A score for how likely the indicator's status is accurate, ranges from 0 to 100}
            {--description=         : A short summary of the indicator and threat}
            {--expired_on=          : Time the indicator is no longer considered a threat, in ISO 8601 date format}
            {--first_active=        : Time when the opinion first became valid}
            {--last_active=         : Time when the opinion stopped being valid}
            {--indicator=           : The data being submitted, e.g. the IP or Domain}
            {--precision=           : UNKNOWN LOW MEDIUM HIGH}
            {--privacy_type=        : VISIBLE HAS_PRIVACY_GROUP HAS_WHITELIST}
            {--privacy_members=     : A comma-delimited list of ThreatExchangeMembers allowed to see the indicator and only applies when privacy_type is set to HAS_WHITELIST}
            {--review_status=       : UNKNOWN UNREVIEWED PENDING REVIEWED_MANUALLY REVIEWED_AUTOMATICALLY}
            {--severity=            : UNKNOWN INFO WARNING SUSPICIOUS SEVERE APOCALYPSE}
            {--share_level=         : RED AMBER GREEN WHITE}
            {--status=              : UNKNOWN NON_MALICIOUS SUSPICIOUS MALICIOUS}
            {--tags=                : A comma separated list of tags you want to publish. This will overwrite any existing tags}
            {--add_tags=            : To add tags to an object without overwriting existing tags}
            {--remove_tags=         : Remove tags associated with an object}
            {--type=                : AS_NUMBER DOMAIN IP_ADDRESS IP_SUBNET URI}
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
        $fields = [
            'confidence',
            'description',
            'expired_on',
            'first_active',
            'last_active',
            'indicator', 
            'precision', 
            'privacy_type',
            'privacy_members',
            'review_status',
            'severity',
            'share_level', 
            'status',
            'tags',
            'add_tags',
            'remove_tags',
            'type',
        ];

        $required_fields = [
            'description',
            'indicator',
            'privacy_type',
            'share_level',
            'status',
            'type',
        ];

        $valid_input = [
            'precision' => [
                'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH',
             ],
            'privacy_type' => [
                'VISIBLE', 'HAS_PRIVACY_GROUP', 'HAS_WHITELIST',
            ],
            'review_status' => [
                'UNKNOWN', 'UNREVIEWED', 'PENDING', 'REVIEWED_MANUALLY', 'REVIEWED_AUTOMATICALLY',
            ],
            'severity' => [
                'UNKNOWN', 'INFO', 'WARNING', 'SUSPICIOUS', 'SEVERE', 'APOCALYPSE',
            ],
            'share_level' => [
                'RED', 'AMBER', 'GREEN', 'WHITE',
            ],
            'status' => [
                'UNKNOWN', 'NON_MALICIOUS', 'SUSPICIOUS', 'MALICIOUS',
            ],
            'type' => [
                'ADJUST_TOKEN', 'API_KEY', 'AS_NUMBER', 'BANNER', 'CMD_LINE', 'COOKIE_NAME', 'CRX', 'DEBUG_STRING',
                'DEST_PORT', 'DIRECTORY_QUERIED', 'DOMAIN', 'EMAIL_ADDRESS', 'FILE_CREATED', 'FILE_DELETED',
                'FILE_MOVED', 'FILE_NAME', 'FILE_OPENED', 'FILE_READ', 'FILE_WRITTEN', 'GET_PARAM', 'HASH_IMPHASH',
                'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'HASH_SSDEEP', 'HTML_ID', 'HTTP_REQUEST', 'IP_ADDRESS',
                'IP_SUBNET', 'ISP', 'LATITUDE', 'LAUNCH_AGENT', 'LOCATION', 'LONGITUDE', 'MALWARE_NAME', 'MEMORY_ALLOC',
                'MEMORY_PROTECT', 'MEMORY_WRITTEN', 'MUTANT_CREATED', 'MUTEX', 'NAME_SERVER', 'OTHER_FILE_OP',
                'PASSWORD', 'PASSWORD_SALT', 'PAYLOAD_DATA', 'PAYLOAD_TYPE', 'POST_DATA', 'PROTOCOL', 'REFERER',
                'REGISTRAR', 'REGISTRY_KEY', 'REG_KEY_CREATED', 'REG_KEY_DELETED', 'REG_KEY_ENUMERATED',
                'REG_KEY_MONITORED', 'REG_KEY_OPENED', 'REG_KEY_VALUE_CREATED', 'REG_KEY_VALUE_DELETED',
                'REG_KEY_VALUE_MODIFIED', 'REG_KEY_VALUE_QUERIED', 'SIGNATURE', 'SOURCE_PORT', 'TELEPHONE', 'URI',
                'USER_AGENT', 'VOLUME_QUERIED', 'WEBSTORAGE_KEY', 'WEB_PAYLOAD', 'WHOIS_NAME', 'WHOIS_ADDR1',
                'WHOIS_ADDR2', 'XPI',
            ],
        ];

        $parameters = [];
        foreach($fields as $field) {
            if(!empty($this->option($field))) {
                $parameters[$field] = $this->option($field);
            }
        }

        foreach($required_fields as $field) {
            if(empty($parameters[$field])) {
                $this->error("required argument --{$field} is missing");
                exit(1);
            }
        }

        foreach($valid_input as $field => $allowed_names) {
            if(!empty($parameters[$field])) {
                if (!in_array($parameters[$field], $allowed_names)) {
                    $this->error("{$parameters[$field]} has to be one of : " . implode(' ', $allowed_names));
                    die();
                }
            }
        }
  
        $url = "{$this->api_url}/{$this->api_version}/threat_descriptors?access_token={$this->application_id}|{$this->application_token}&";

        $results = json_decode($this->doApiPostRequest($url, $parameters), true);

        if($results['success'] === true){
            $this->info("Sucessfully submitted threat descriptor {$parameters['type']} {$parameters['indicator']}");
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
