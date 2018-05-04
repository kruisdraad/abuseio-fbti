<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use MongoDB;
use Log;

class CspController extends Controller {
    public function __construct()
    {
        //
    }

    public function report(Request $request) {
        $csp_data = json_decode($request->getContent(), true);

        $collection = (new MongoDB\Client)->fbti->csp_reports;
        $insertResult = $collection->insertOne($csp_data);

        Log::info(
            "CSP-REPORT saved into database under ID : {$insertResult->getInsertedId()}" . json_encode($csp_data,true)
        );

        return response('', 200);
    }
}