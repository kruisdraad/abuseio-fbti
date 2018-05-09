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
class WorkerRetryCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = "worker:retry
      ";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Searches for buried jobs in all the queues and retries them";

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
        $connection = env('BS_HOST') . ':' . env('BS_PORT');
        $pheanstalk = new Pheanstalk($connection);

        $usage = [];
        $prefix = 'worker_queue_';
        foreach($pheanstalk->listTubes() as $tube) {
            if (strncmp($tube, $prefix, strlen($prefix)) !== 0) {
                continue;
            }

            $tubeStats = $pheanstalk->statsTube($tube);

            $buriedCount = $tubeStats['current-jobs-buried'];
            if($buriedCount != 0) {
                $this->info("Tube {$tube} has {$buriedCount} buried items");

                for($i = 1; $i <= $buriedCount; $i++) {
		    $buriedJob = $pheanstalk->peekBuried($tube);
                    $pheanstalk->kickJob($buriedJob);
                    $this->info("Job with ID {$buriedJob->getId()} kicked back into the queue");
                }
            }
        }
        $this->info("Completed checks for buried jobs");
    }
}
