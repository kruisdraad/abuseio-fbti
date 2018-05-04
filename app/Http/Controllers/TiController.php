<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Webpatser\Uuid\Uuid;
use MongoDB;
use Log;

class TiController extends Controller {

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

    /**
     * The debug flag, for extended logging
     *
     * @var string
     */
    protected $debug_mode = false;

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
        $mode  = $request->get('hub_mode');
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

        if ($this->debug_mode) {
            $this->LogInfo("Received the following data package: " . json_encode($webhook_data, true));
        }

        foreach ($webhook_data as $element => $data) {
            switch($element) {
                case 'entry':
                    $this->handleEntries($data);
                    break;

                case 'object':
                    break;

                default:
                    $this->logError("Received an invalid webhook request, ignoring request");
            }
        }

        if ($this->job_error) {
            $this->logError("An error has occurred while receiving the following data package: " . json_encode($webhook_data, true));
        }

        //	The following can be used to do a response back
        //  $this->dispatchResponse($sender, 'Collection event has been trigger, thanks for the update!.');

        return response('', 200);
    }

    protected function handleEntries($entries) {
        foreach($entries as $entryId => $entryData) {
            foreach($entryData as $updateType => $updateData) {
                switch($updateType) {
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

    protected function handleEntryChanges($changes) {
        $allowed_fields = [
            'malware_analyses',
            'malware_families',
            'threat_descriptors',
            'threat_indicators',
            'threat_tags_descriptors',
        ];

        foreach($changes as $changeIndex => $changeData) {
             if (!in_array($changeData['field'], $allowed_fields)) {
                 return $this->logError("Received an invalid entry change message, ignoring message");
             }
             $field = $changeData['field'];
             $values = $changeData['value'];

             $collection = (new MongoDB\Client)->fbti->$field;
             $updateResult = $collection->updateOne(
                 ['id' => $values['id']],
                 ['$set' => $values],
                 ['upsert' => true]
             );

            $this->logInfo(
                "Database Update Type: {$field} ".
                "Matched: {$updateResult->getMatchedCount()} ".
                "Modified: {$updateResult->getModifiedCount()} ".
                "Inserted:{$updateResult->getUpsertedCount()} ".
                "ObjectID: {$updateResult->getUpsertedId()}");

         }

        return true;
    }

    protected function logError($message) {
        Log::error('JOB: ' . $this->job_id . ' WEBHOOK ' . $message);

        $this->job_error = true;

        return false;
    }

    protected function logInfo($message) {
        Log::info('JOB: ' . $this->job_id . ' WEBHOOK ' . $message);

        return true;
    }


    /**
     * Post a message to the Facebook Ti API.
     *
     * @param  integer $id
     * @param  string  $response
     * @return bool
     */
    protected function dispatchResponse($id, $response)
    {
        $access_token = env('TI_PAGE_ACCESS_TOKEN');
        $url = "https://graph.facebook.com/v2.6/me/messages?access_token={$access_token}";

        $data = json_encode([
            'recipient' => ['id' => $id],
            'message'   => ['text' => $response]
        ]);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        $result = curl_exec($ch);
        curl_close($ch);

        return $result;
    }
}
