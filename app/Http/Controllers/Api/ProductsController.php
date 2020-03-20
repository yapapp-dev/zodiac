<?php

namespace App\Http\Controllers\Api;


use App\Notifications\SignupActivate;
use Illuminate\Http\Request; 
use App\Http\Controllers\Controller; 
use App\Product; 
use Illuminate\Support\Str;
use Validator;


class ProductsController extends Controller   
{ 
    public $successStatus = 200;
    
    public function __construct()
    {
        //$this->middleware(['auth','admin']); 
    }

    public function addProduct(Request $request){

        $validator = Validator::make($request->all(), [ 
            'shop_id' => 'required',
            'name' => 'required',
            'quantity' => 'required|numeric',
            'price' => 'required|numeric',
        ]);


        if ($validator->fails()) { 
            $errors = $validator->errors()->all();
                $result = array(
                    "statusCode" => 401,  // $this-> successStatus
                    "message" => $errors[0]
                );
            return response()->json($result );            
        }
        $input = $request->all(); 
        $productObj = Product::create($input);

        if($productObj){
            $result = array(
				"statusCode" => 200,  // $this-> successStatus
				"message" => "success",
				"data" => $productObj
			);

            return response()->json($result);
        } else {
            $result = array(
				"statusCode" => 500,  // $this-> successStatus
				"message" => "Unable to add product. Please try again later."	
			);
            return response()->json($result); 
        }
    }
}