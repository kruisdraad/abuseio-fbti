<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Carbon\Carbon;
use Illuminate\Support\Facades\Storage;
use Log;

class HomeController extends Controller {
    public function __construct()
    {
        //
    }

    public function index(Request $request) 
    {
        $response = 'OK';

        return response($response, 200);
    }
}
