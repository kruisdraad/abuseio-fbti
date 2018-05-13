<?php
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;
use Pheanstalk\Pheanstalk;
use Webpatser\Uuid\Uuid;
use Exception;

/**
 * Class ThreatexSync
 *
 * @category Console_Command
 * @package  App\Console\Commands
 */
class JobRetryCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = "job:retry
      {file : The file containing the report in JSON format from the failed_objects dir 'date/hr/file.json'}
      {--delete=false : Delete the file if successfully processed}
      ";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Retries a failed job file";

    /**
     * The job ID, for log prefixing
     *
     * @var string
     */
    protected $job_id = false;

    /**
     * The file for processing
     *
     * @var string
     */
    private $file;

    /**
     * The file for processing
     *
     * @var boolean
     */
    private $delete_after;

    /**
     * Create a new command instance.
     */
    public function __construct()
    {
        parent::__construct();
        $this->job_id = (string)Uuid::generate(4);
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     * @throws
     */
    public function handle()
    {

        $this->file = 'failed_objects/' . $this->argument('file');
        if ($this->option('delete') === null) {
            $this->delete_after = true;
        } else {
            $this->delete_after = false;
        }

        if (!Storage::exists($this->file)) {
            return $this->error("The file {$this->file} does not exist");
        }

        $data = json_decode(Storage::get($this->file), true);

        $this->createBeanstalk($data);

        if($this->delete_after) {
            Storage::delete($this->file);
        }

        $this->info("Completed re-entry of failed job. Check the logs with above ID's for results.");
    }

    private function createBeanstalk($data) {
        $connection = env('BS_HOST') . ':' . env('BS_PORT');
        $pheanstalk = new Pheanstalk($connection);

        if(!$pheanstalk->getConnection()->isServiceListening()) {
            $this->error('Beanstalk is NOT running, fallback to saving onto filesystem as failed object');
            return false;
        }

        $queue = $this->selectTube($pheanstalk);

        $job = $pheanstalk
            ->useTube($queue)
            ->put(json_encode([ 'type' => 'TiSaveReport', 'id' => $this->job_id, 'data' => $data]));

        if (!is_numeric($job)) {
            $this->error('Unable to push job into beanstalk queue, fallback to saving onto filesystem as failed object' . json_encode($job));
            return false;
        }

        $this->info("Queued job into {$queue} with ID : {$job} and UUID : {$this->job_id}");

        return true;
    }

    /*
     * Selects the tube based on how empty they are
     * Todo: add config setting to select mode?
     */
    private function selectTube($queue) {
        $usage = [];
        $prefix = 'worker_queue_';
        foreach($queue->listTubes() as $tube) {
            if (strncmp($tube, $prefix, strlen($prefix)) !== 0) {
                continue;
            }

            $tubeStats=$queue->statsTube($tube);

            $usage[$tube] =
                    $tubeStats['current-jobs-ready'] +
                    $tubeStats['current-jobs-urgent'] +
                    $tubeStats['current-jobs-reserved'] +
                    $tubeStats['current-jobs-delayed'];
        }

        asort($usage);
        reset($usage);

        return key($usage);
    }

}
