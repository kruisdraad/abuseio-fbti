<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use MongoDB;
use Config;
use Log;

class HomeController extends Controller {
    public function __construct()
    {
        //
    }

    public function index(Request $request) {
        var_dump(Config::get('database.connections.mysql.host'));

        return response('', 200);
    }
}