<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use MongoDB;
//use Config;
use Log;

class HomeController extends Controller {
    public function __construct()
    {
        //
    }

    public function index(Request $request) {
        var_dump(config());

        return response('', 200);
    }
}
