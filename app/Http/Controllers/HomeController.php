<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Carbon;
use Storage;
use Log;

class HomeController extends Controller {
    public function __construct()
    {
        //
    }

    public function index(Request $request) 
    {
        // test
        $date = Carbon::now()->format('Ymd');
        $path = 'failed_objects/'.$date;
        $file = '1337' . '.json';

        umask(0007);

        if (!Storage::exists($path)) {
            if (!Storage::makeDirectory($path, 0770)) {
                Log::error(
                    get_class($this) . ': ' .
                    'Unable to create directory: ' . $path
                );
            }
        }

        if (Storage::put( $file, json_encode($request->all()) ) === false) {
            Log::error(
                get_class($this).': '.
                'Unable to write file: '.$file
            );
        }

	    $response = 'OK';

        return response($response, 200);
    }
}
