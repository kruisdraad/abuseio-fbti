<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use MongoDB;
use Log;

class HomeController extends Controller {
    public function __construct()
    {
        //
    }

    public function index(Request $request) {


        return response('', 200);
    }
}