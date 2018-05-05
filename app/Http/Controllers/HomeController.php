<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Log;

class HomeController extends Controller {
    public function __construct()
    {
        //
    }

    public function index(Request $request) 
    {
        return response('OK', 200);
    }
}
