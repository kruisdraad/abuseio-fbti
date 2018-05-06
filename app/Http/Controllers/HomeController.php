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
	$response = 'OK';

        return response($response, 200);
    }
}
