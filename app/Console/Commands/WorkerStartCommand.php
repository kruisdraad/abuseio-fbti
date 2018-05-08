<?php
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;
use Pheanstalk\Pheanstalk;
use Exception;
use Log;

/**
 * Class ThreatexSync
 *
 * @category Console_Command
 * @package  App\Console\Commands
 */
class WorkerStartCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = "worker:start
      {queue : The queue the worker should participate in}
      ";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Starts a worker for a specific queue";

    /**
     * The file for processing
     *
     * @var string
     */
    private $queue;

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
        $this->queue = $this->argument('queue');

        $connection = env('BS_HOST') . ':' . env('BS_PORT');
        $queue = new Pheanstalk($connection);

        $queue->watch($this->queue);

        while (true) {
            if (!$job = $queue->reserve()) {
                continue;
            }
            try {
                $jobData = json_decode($job->getData(), true);

                $type = $jobData['type'];
                $uuid = $jobData['id'];
                $data = $jobData['data'];
                $class= '\\App\\Jobs\\' . $type;

                Log::info("Job with UUID {$uuid} has been plucked from the queue");

                $handler = new $class($uuid, $data);
                if ($handler->handle()) {
                    Log::info("Job with UUID {$uuid} has completed and removed from the queue");
                    $queue->delete($job);
                } else {
                    Log::info("Job with UUID {$uuid} has failed and buried in the queue");
                    $queue->bury($job);
                }
            } catch (Exception $e) {
                Log::info("Job with UUID {$uuid} has faulted and buried in the queue. reason: {$e->getMessage()}");
                $queue->bury($job);
            }
        }
    }
}
