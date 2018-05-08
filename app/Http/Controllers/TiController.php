<?php
namespace App\Http\Controllers;

use Illuminate\Support\Facades\Storage;
use Illuminate\Http\Request;
use Pheanstalk\Pheanstalk;
use Webpatser\Uuid\Uuid;
use Carbon\Carbon;
use Exception;
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
     * The job ID, for log prefixing
     *
     * @var string
     */
    protected $job_id = false;

    protected $startup = false;

    public function __construct()
    {
        $this->notify_token = env('TI_NOTIFY_TOKEN');
        $this->job_id = (string)Uuid::generate(4);
        $this->startup = Carbon::now();
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
        // Missing auth?!?!?
        $data = $request->all();

        try {
            if(!$this->createBeanstalk($data)) {
                if(!$this->createFailedFile($data)) {
                    Log::error('Could not even write failed job file, installation bad?');
                }
            }
        } catch (Exception $e) {
            if(!$this->createFailedFile($data)) {
                Log::error('Could not even write failed job file, installation bad?');
            }

            Log::error('Error pushing job into queue, reason: ' . $e->getMessage());
        }

        return response('ok', 200);
    }

    private function createBeanstalk($data) {
        $connection = env('BS_HOST') . ':' . env('BS_PORT');
        $pheanstalk = new Pheanstalk($connection);

        if(!$pheanstalk->getConnection()->isServiceListening()) {
            Log::error('Beanstalk is NOT running, fallback to saving onto filesystem as failed object');
            return false;
        }

        $queue = 'worker_queue_' . intval($this->startup->format('s'));

        $job = $pheanstalk
            ->useTube($queue)
            ->put(json_encode([ 'type' => 'TiSaveReport', 'id' => $this->job_id, 'data' => $data]));

        if (!is_numeric($job)) {
            Log::error('Unable to push job into beanstalk queue, fallback to saving onto filesystem as failed object' . var_dump($job));
            return false;
        }

        Log::info("Queued job into {$queue} with ID : {$job} and UUID : {$this->job_id}");

        return true;
    }

    private function createFailedFile($data) {
        $date = $this->startup->format('Ymd');
        $hour = $this->startup->format('H');
       
        $path = "failed_objects/{$date}/{$hour}";
        $file = "{$path}/{$this->job_id}.json";

        if (!Storage::exists($path)) {
            if (!Storage::makeDirectory($path, 0770)) {
                Log::error('Unable to create directory: ' . $path);
                return false;
            }
        }

        if (Storage::put( $file, json_encode($data) ) === false) {
            Log::error('Unable to write file: ' . $file);
            return false;
        }

        Log::info('failed job file saved at : ' . $file);

        return true;
    }

}
