<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use MongoDB;
use Log;

class PkpController extends Controller {
    public function __construct()
    {
        //
    }

    public function report(Request $request) {
        $pkp_data = json_decode($request->getContent(), true);

        $collection = (new MongoDB\Client)->fbti->pkp_reports;
        $insertResult = $collection->insertOne($pkp_data);

        Log::info(
            "PKP-REPORT saved into database under ID : {$insertResult->getInsertedId()}" . json_encode($pkp_data,true)
        );

        return response('', 200);
    }
}