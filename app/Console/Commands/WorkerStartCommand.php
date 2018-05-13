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
    private $worker;

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
        $this->worker = strtoupper($this->queue);

        Log::info($this->worker . ": Starting up worker");

        $connection = env('BS_HOST') . ':' . env('BS_PORT');
        $pheanstalk = new Pheanstalk($connection);

        while (true) {
            
            try {
                $job = $pheanstalk
                    ->watch($this->queue)
                    ->ignore('default')
                    ->reserve();
                $jobData = json_decode($job->getData(), true);

                $type = $jobData['type'];
                $uuid = $jobData['id'];
                $data = $jobData['data'];
                $class= '\\App\\Jobs\\' . $type;

                Log::info($this->worker . ":Job with ID {$job->getId()} and UUID {$uuid} has been plucked from the queue");

                if(!class_exists($class)) {
                    Log::info($this->worker .":Job with UUID {$uuid} wants to use class {$class} which does not exist");
                    $pheanstalk->bury($job);
                }

                $handler = new $class($uuid, $data);
                if ($handler->handle()) {
                    Log::info($this->worker . ":Job with UUID {$uuid} has completed and removed from the queue");
                    $pheanstalk->delete($job);
                } else {
                    Log::info($this->worker .":Job with UUID {$uuid} has failed and buried in the queue");
                    $pheanstalk->bury($job);
                }
            } catch (Exception $e) {
                if(empty($uuid)) {
                    Log::error($this->worker . ":Worker faulted reason: {$e->getMessage()}");
                } else {
                    Log::error($this->worker . ":Job with UUID {$uuid} has faulted and buried in the queue. reason: {$e->getMessage()}");
                }

                $pheanstalk->bury($job);
            }
        }
    }
}
