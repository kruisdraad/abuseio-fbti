<?php

namespace App\Console;

use Illuminate\Console\Scheduling\Schedule;
use Laravel\Lumen\Console\Kernel as ConsoleKernel;

class Kernel extends ConsoleKernel
{
    /**
     * The Artisan commands provided by your application.
     *
     * @var array
     */
    protected $commands = [
        Commands\ThreatexSyncCommand::class,
        Commands\ThreatexSubmitCommand::class,
        Commands\ThreatexSubscribeCommand::class,
        Commands\ThreatexSubscriptionsCommand::class,
        Commands\WorkerRetryCommand::class,
        Commands\WorkerFlushCommand::class,
        Commands\WorkerStartCommand::class,
	Commands\WorkerEnrichCommand::class,
        Commands\JobRetryCommand::class,
    ];

    /**
     * Define the application's command schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    protected function schedule(Schedule $schedule)
    {
        //
    }
}
