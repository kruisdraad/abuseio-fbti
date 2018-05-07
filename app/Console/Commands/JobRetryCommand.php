<?php
namespace App\Console\Commands;

use App\Jobs\TiSaveReport;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

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
      {file : The file containing the report in JSON format}
      ";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Create a job to retry a failed report";

    /**
     * The file for processing
     *
     * @var string
     */
    private $file;

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
        $this->file = $this->argument('file');

        if (!Storage::exists($this->file)) {
            $this->error("The file {$this->file} does not exist");
        }

        $data = json_decode(Storage::get($this->file), true);

        dispatch(new TiSaveReport($data));

        return true;
    }
}
