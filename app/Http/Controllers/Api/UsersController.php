<?php

namespace App\Http\Controllers\Api;


use App\Notifications\SignupActivate;
use Illuminate\Http\Request; 
use App\Http\Controllers\Controller; 
use App\User; 
use DB;
use App\Userservice;
use App\Userlocation;
use App\Banners; 
use App\Service;
use App\Location;
use App\Products;
use App\category;
use Illuminate\Support\Facades\Auth;  
use Validator;
Use App\Address;
use App\Orders;
use App\ContactUS;
use Illuminate\Support\Facades\Mail;
use App\Http\Controllers\notificationController;
use Notification;
use App\Notifications\OrderAlert;
use App\Http\Controllers\CurrencyController;
use App\SocialUsers;
use App\Subservices;
use App\dpoPayments;
use App\Notifications\ContactUsNoti;
use Illuminate\Support\Str;
use App\Notifications\CustomNoti;
use App\Notifications\SendResetPasswordOTP;
use App\Shop;



class UsersController extends Controller   
{ 

public $successStatus = 200;
 public function __construct()
    {
        //$this->middleware(['auth','admin']); 
    }

/** 
     * login api 
     * 
     * @return \Illuminate\Http\Response 
     */ 
    public function login(Request $request){ 
		$error="";

		if(!$request->has('admin') || $request->input('admin') == ''){
			$error = "Field admin is mandatory";
		}
		if(!$request->has('fcm_token') || $request->input('fcm_token') == ''){
			$error = "fcm_token field is mandatory";
		}

		if(!$request->has('device_type') || $request->input('device_type') == ''){
			$error = "device_type field is mandatory";
		}

		if($error != "") {
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => $error	
			);
			return response()->json($result ); 
		}
		if(is_numeric($request->get('email_mobile'))) {
			$val = Auth::attempt(['phone' => request('email_mobile'), 'password' => request('password'), 'admin' => request('admin')]);
        } else {
			$val = Auth::attempt(['email' => request('email_mobile'), 'password' => request('password'), 'admin' => request('admin')]);
		}
        if($val) { 		
            $user = Auth::user(); 

			// if ($user['is_activated'] == 0) {
			// 	$result = array(
			// 		"statusCode" => 707,  // $this-> successStatus
			// 		"message" => "You are not active user."	
			// 		);
			// 	return response()->json($result );            
			// }
			
			if ($user['phone_verified'] == 0 && $user['email_verified'] == 0) {
				$result = array(
					"statusCode" => 708,  // $this-> successStatus
					"message" => "Verify Your Email/Phone First."
				);
				return response()->json($result );            
			}

			$user->fill([
				'fcm_token' => $request->input('fcm_token'),
				'device_type' => $request->input('device_type')
			]);
			$user->save();

            $success['token'] =  $user->createToken('MyApp')->accessToken; 
            
            $user->token = $success['token'];

			$user_data = $user;

			if($user["image"]!='')
				$user_data["image"] = url('/')."/images/profile/".$user['id']."/".$user["image"];

			// $UserDetails = DB::table('business')->where('user_id', $user['id'])->get();
			// if($UserDetails->isNotEmpty()) {
			// 	$user_data["more_details"] = $UserDetails[0];
			// } 

			// if(session('currencyselected')) $currencyselected=session('currencyselected'); else $currencyselected=150; 
			// $user_data["reward_points"] = $user->currentPoints();
			// $user_data["reward_value"] = \Config::get('constants.redeem_rate')*$user_data["reward_points"];

			// if($request->has('currency') && $request->input('currency')!='') {
			// 	$currency_id = $request->input('currency');
			// 	$exchangerate = $this->exchangerate($currency_id);
			// 	$exchangerate['currency']=$currency_id;
			// } else $exchangerate = array();

            $result = array(
				"statusCode" => 200,  // $this-> successStatus
				"message" => "success",
				"data" => $user_data
			);

            return response()->json($result); 
        }  else { 
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "Invalid Email Or Password."	
			);
            return response()->json($result); 
        } 
	}
		
/** 
     * Register api 
     * 
     * @return \Illuminate\Http\Response 
     */ 
    public function register(Request $request)  { 
		if($request->has('social') && $request->input('social')!='' && (!$request->has('social_id') || $request->input('social_id')=='')){
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "social_id is required with social",
				
			);
			return response()->json($result); 
		}

		if($request->has('social_id') && $request->input('social_id')!='' && (!$request->has('social') || $request->input('social')=='')){
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "social is required with social_id",
				
			);
			return response()->json($result); 
		}

		$admin = $request->input('admin');

			$validator = Validator::make($request->all(), [ 
				'name' => 'required',
				'email_mobile' => 'required|unique:users,email|unique:users,phone', 
				'password' => 'required'
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
		$data['name'] = $input['name']; 
		$data['password'] = bcrypt($input['password']);

		if(is_numeric($input['email_mobile'])){
			$data['phone'] = $input['email_mobile'];
			$data['email'] = $input['email_mobile']."@mrnice.com";
		}
		else{
			$data['email'] = $input['email_mobile'];
		}
		

		$activation_token = Str::random(60);
		$data['activation_token'] = $activation_token;

		
			
		$user = User::create($data); 
		
		$otp = substr(mt_rand(1000,10000000000), 0, 4);

	
		
		$success['token'] =  $user->createToken('MyApp')->accessToken; 
		$success['data']  =  $user; 
		
		if(is_numeric($input['email_mobile'])){
			
		    // tiwilio
		  	
		}
		else{

			DB::table('user_activations')->insert(['id_user'=>$user['id'],'token'=>$activation_token]);
			
			
			$user->subject = 'OTP Verification';
			$user->line1 = "Hi ".$user->name;
			$user->line2 = "Your OTP verification code is $otp";
			//$user->line6 = "Click below button to approve.";
			$user->action_label = "Mr. Nice";
			$user->action = "/";
			$user->notify(new CustomNoti($user));
		}

		

		
		$result = array(
			"statusCode" => 200,  // $this-> successStatus
			"message" => "success",
			"data" => $success,
			"otp" => $otp
		);
		return response()->json($result); 
	}

	public function verifyUser(Request $request) {
		
		if (Auth::user()) { 
			//$user = Auth::user(); 

			if(!$request->has('user_id') || $request->input('user_id') == ''){
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "user_id is required."	
				);
				return response()->json($result); 
			}

			$user = User::find($request->user_id);
			$user->email_verified = 1;
			$user->phone_verified = 1;
			$user->save();


			$result = array(
				"statusCode" => 200,  // $this-> successStatus
				"message" => "success",
				"data" => $user
			);
			return response()->json($result);
		}
		else {
			return response()->json([
				'message' => 'Sorry! But you are not an authorized user.'
			]);
		}
		
	}

	public function verifyOtp(Request $request) {
		
		$otp = DB::table('otp')->where('user_id', $request->id)->where('otp', $request->otp)->whereNull('expired_at')->count();

		if($otp > 0) {
			$user = User::find($request->id);
			$user->mobile_verified_at = date("Y-m-d",time());
			$user->phone_verified = 1;
			$user->save();

			Auth::loginUsingId($request->id, TRUE);
			$result = array(
				"statusCode" => 200,  // $this-> successStatus
				"message" => "Thanks! Your mobile no. has been verified successfully."
			);
		} else {
			$result = array(
				"statusCode" => 400,  // $this-> successStatus
				"message" => "Oops! Invalid OTP suspected."
			);
		}
		return response()->json($result); 
	}

	public function sendOtp(Request $request) {
		$user = User::find($request->id);
		$otp = substr(mt_rand(1000,10000000000), 0, 4);
		$mobileMessage = $this->mobileMessage($user->phone,"Your MrNice verification OTP is $otp.");
		$t=time();
		DB::table('otp')
			->where('user_id', $request->id)
			->update(array('expired_at' => date("Y-m-d",$t))); 

		DB::table('otp')->insert([
			'user_id'     => $user['id'],
			'mobile'      => $user->phone,
			'otp'         => $otp,
			'created_at'  => date("Y-m-d",$t)
		]);

	
		$result = array(
			"statusCode" => 200,  // $this-> successStatus
			"message" => "OTP has been sent successfully."
		);

		return response()->json($result); 
	}
	public function mobileMessage($mobile,$message) {
		$numbers = urlencode($mobile);
		$sender = urlencode('MrNice');
		$apiKey = urlencode('qCyIIcBC5W0-EVjmXfLvruLq2XUrVXV0UvnJcR4sUv');
		$data = array('apikey' => $apiKey, 'numbers' => $numbers, "sender" => $sender, "message" => $message);
			// Send the POST request with cURL
			$ch = curl_init('https://api.textlocal.in/send/');
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response = curl_exec($ch);
			curl_close($ch);
			return $response;
	}
/** 
     * details api 
     * 
     * @return \Illuminate\Http\Response 
     */ 
    public function details(Request $request) {  
		if (Auth::user()) { 
			$user = Auth::user(); 
			//print_r($user);

			if(!$request->has('user_id') || $request->input('user_id') == ''){
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "user_id is required."	
				);
				return response()->json($result); 
			}

			$user = User::find($request->user_id);

			if ($user['phone_verified'] == 0 && $user['email_verified'] == 0) {
				$result = array(
					"statusCode" => 707,  // $this-> successStatus
					"message" => "You are not an active user."
					);
				return response()->json($result );            
			}
	
			//$UserDetails = DB::table('business')->where('user_id', $user['id'])->get();

			if($user["image"] != '')
			$user["image"] = url('/')."/images/profile/".$user['id']."/".$user["image"];

			// if($UserDetails->isNotEmpty()){
			// 	$user["more_details"] = $UserDetails[0];
			// }

			$result = array(
				"statusCode" => 200,  // $this-> successStatus
				"message" => "success",
				"data" => $user
			);
			return response()->json($result);
		}
		else{
			return response()->json([
				'message' => 'Sorry! But you are not an authorized user.'
			]);
		}
		
    }
	public function sociallogin(Request $request)
    {
		$error = "";
		if(!$request->has('social') || $request->input('social') == ''){
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "social type is required. Please get back with it."	
			);
			return response()->json($result); 
		}

		if(!$request->has('social_id') || $request->input('social_id') == ''){
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "social_id is required",
				
			);
			return response()->json($result); 
		}

		if(!$request->has('fcm_token') || $request->input('fcm_token') == ''){
			$error = "fcm_token field is mandatory";
		}

		if(!$request->has('device_type') || $request->input('device_type')==''){
			$error = "device_type field is mandatory";
		}

		if($error != ""){
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => $error,
					
			);
			return response()->json($result ); 
		}
		$social = $request->input('social');
		$social_id = $request->input('social_id');
		$social_image = $request->input('social_image');
		$social_name = $request->input('social_name');
		$social_email = $request->input('social_email');

		$user_data = User::where('social', $social)->where('social_id', $social_id)->first();
		if ($user_data) { 
			if($user_data->is_activated == 0){
				$result = array(
					"statusCode" => 707,  // $this-> successStatus
					"message" => "You are not an active user.");
				return response()->json($result);            
			}

			if($user_data->phone_verified == 0){
				$result = array(
					"statusCode" => 708,  // $this-> successStatus
					"message" => "Your phone number is not verified. Please make sure to do it as soon as   possible.");
				return response()->json($result);            
			}

			$loggedInUser = Auth::loginUsingId($user_data->id, true);
			$loggedInUser->fill([
				'fcm_token' => $request->input('fcm_token'),
				'device_type' => $request->input('device_type')
			]);
			$loggedInUser->save();

			if($loggedInUser["image"] != '')
				$loggedInUser["image"] = url('/')."/images/profile/".$loggedInUser['id']."/".$loggedInUser["image"];
				
				// if(session('currencyselected')) $currencyselected=session('currencyselected'); else $currencyselected=150; 
				// $loggedInUser["reward_points"] = $loggedInUser->currentPoints();
				// $loggedInUser["reward_value"] = \Config::get('constants.redeem_rate')*$loggedInUser["reward_points"];

			$success['token'] =  $loggedInUser->createToken('MyApp')->accessToken; 
				
			$loggedInUser->token = $success['token'];

			$result = array(
				"statusCode" => 200, 
				"message" => "success",
				"data" => $loggedInUser
			);
    	} else {
			SocialUsers::firstOrCreate([
				'social' => $social,  
				'social_id' => $social_id, 
				'social_image' => $social_image, 
				'social_name' => $social_name, 
				'social_email' => $social_email
			]);

			$result = array(
				"statusCode" => 709, 
				"message" => "Your social data has been saved successfully.");
		}
		
		return response()->json($result);
	}
	
    public function changePassword(Request $request) { 
		
		if(!$request->has('user_id') || $request->input('user_id') == ''){
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "user_id is required."	
			);
			return response()->json($result); 
		}

		$userId = $request->input('user_id');
		$user = User::where('id', $userId)->first();
		
		if(!$user){
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "User does not exist with this user id."	
			);
			return response()->json($result); 
		}
		
		if ($user) {			
			$input = $request->all();			
			if(!empty($input['new_password'])) {
				// $user = Auth::user();				
				$user->password = bcrypt($input['new_password']);
				$user->save();	
				$result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "Hurray! Your password has been successfully changed.",
					"data" => $user);
			} else {
				$result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "Please make sure to mention the required password field.");	
			}		
			return response()->json($result);
		} else {
			return response()->json([
				'message' => 'Sorry! But you are not an authorized user.'
			]);
		}			
    }
	
	public function forgotPassword(Request $request) {
		// if (Auth::user()) { 
			//$user = Auth::user(); 

			if(!$request->has('user_id') || $request->input('user_id') == ''){
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "user_id is required."	
				);
				return response()->json($result); 
			}

			$userId = $request->input('user_id');

			if(filter_var($userId, FILTER_VALIDATE_EMAIL)){
				$user = User::where('email', $userId)->first();	
			} else {
				$user = User::where('phone', $userId)->first();	
			}
			
			if(!$user){
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "User does not exist with this user id."	
				);
				return response()->json($result); 
			}

			$resetPasswordOtp = mt_rand(1000000, 9999999);
			$userObj = $user;
			$user->reset_password_otp = $resetPasswordOtp;
			$hasSaved = $user->save();

			if($hasSaved){
				if(filter_var($userId, FILTER_VALIDATE_EMAIL)){
					$userObj->subject = 'Reset Password OTP';
					$userObj->line1 = "Hi ".$userObj->name;
					$userObj->line2 = "Your reset password OTP is $resetPasswordOtp";
					//$user->line6 = "Click below button to approve.";
					$userObj->action_label = "Mr. Nice";
					$userObj->action = "/";

					$userObj->notify(new SendResetPasswordOTP($userObj));
				} else {
					// TO DO
					// Send otp on phone number
				}
				
				$result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "Reset password OTP has been sent.",
					"data" => [
						'user_id' => $userId
					]
				);
				return response()->json($result);

				// return response()->json(['test' => $userObj]); 
			}
		
	}

	public function resetPassword(Request $request) {
		// if (Auth::user()) { 
			//$user = Auth::user(); 
			$validator = Validator::make($request->all(), [ 
				'user_id' => 'required',
				'reset_password_otp' => 'required',
				'new_password' => 'required',
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

			if(filter_var($input['user_id'], FILTER_VALIDATE_EMAIL)){
				$query = User::where('email', $input['user_id']);	
			} else {
				$query = User::where('phone', $input['user_id']);	
			}
			$userObj = $query->where('reset_password_otp', $input['reset_password_otp'])->first();

			if(!$userObj){
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "User does not exist with these details."	
				);
				return response()->json($result); 
			}

			$userObj->password = bcrypt($input['new_password']);
			$userObj->reset_password_otp = null;

			if($userObj->save()){
				$result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "Password updated successfully."
				);
				
			} else {
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "Unable to change password. Please try again later.",
				);
			}
			return response()->json($result);			
	}

	public function updateprofile(Request $request) { 
		if (Auth::user()) {
			$user = Auth::user();	

			if ($user->is_activated==0) {
				$result = array(
					"statusCode" => 707,  // $this-> successStatus
					"message" => "You are not an active user.");
				return response()->json($result );            
			}

			if ($user->phone_verified == 0) {
				$result = array(
					"statusCode" => 708,  // $this-> successStatus
					"message" => "Your phone number is not verified. Please make sure to do it as soon as   possible."	
				);
				return response()->json($result );            
			}
					
			$validator = Validator::make($request->all(), [ 
				'email' => 'email|unique:users', 
				'phone' => 'numeric|digits_between:6,15|unique:users',
				'date_of_birth' => 'date|date_format:Y-m-d'
			]);

			if ($validator->fails()) {
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "error",
					"data" => $validator->errors() 
				);
				return response()->json($result );            
			}	
				
			$input = $request->all();	
			// dd($input);
			if ($request->hasFile('image')) {
				$input['image'] = time() . '.' . 
				$request->file('image')->getClientOriginalExtension();
				$request->file('image')->move(
					'/var/www/html/hobyclean/public/images/profile/'.$user->id.'/', $input['image']
					);
			} else {
				$request->request->remove('image');
			}

			$statusCode=200;
			$result_message = "success";

			$mobile_verified_at = $user->mobile_verified_at;
			if($request->has('phone') && $user->phone != $input['phone']){
				$input['is_activated'] = 0;
				$input['phone_verified'] = 0;
				$statusCode = 707;
				$result_message = "You are no longer an active user. Please verify your phone number.";
				$mobile_verified_at = null;
			}

			$activation_token = Str::random(60);
			$input['activation_token'] = $activation_token;
						
			$req =$input;
			$user->fill($input);

			if($user->save()){
				if($mobile_verified_at == null) {
					DB::table('user_activations')->insert(['id_user'=>$user->id,'token'=>$activation_token]);
					$user->notify(new SignupActivate($user));
				}
				$user["image"] = url('/')."/images/profile/".$user->id."/".$user->image;
				$result = array(
					"statusCode" => $statusCode,  // $this-> successStatus
					"message" => $result_message,
					"data" => $user
				);

			} else {
				$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "Oops! Please try again. We are finding some issue in updating database."
				);
			}					
						
			return response()->json($result);
		} else { 
			$result = array(
				"statusCode" => 401,  // $this-> successStatus
				"message" => "Sorry but you are not an authorized user."
				);			
			return response()->json($result);
		}
			
    }
    
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();        
        $result = array(
				"statusCode" => 200,  // $this-> successStatus
				"message" => "success",
				"data" =>'Successfully logged out'
			);
        return response()->json($result );  
    }
    
    
    /** 
     * details api 
     * 
     * @return \Illuminate\Http\Response 
     */ 
    // public function servicelist() 
    // {  

		// //$banner = Banners::all();		
		// $user = Auth::user(); 
		// $services = Service::all();
		// //$products = Products::all();
		// $service_new =  array();
		// foreach($services as $service){			
		// 	$service['image'] = url('/').'/img/icons/32/database.png';
		// 	$service['products'] =Products::where('service_id','=',$service['id'])->get();
		// 	array_push($service_new, $service);
		// }
		// $result = array(
		// 			"statusCode" => 200,  // $this-> successStatus
		// 			"message" => "success",
		// 			"data" => array('services' => $service_new)
		// 		);
		
		// return response()->json($result);
    // }


	public function rewardpoints()
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}

				 $reward["reward_points"] = $user->currentPoints();
				 $reward["reward_value"] = \Config::get('constants.redeem_rate')*$reward["reward_points"];
      
				 $result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => $reward
		
						);
						
						return response()->json($result);


		}

    public function exchangerate($currency_id) {
        
			$res = currencies::select('code','exchange_rate')->where('id',$currency_id)->get();
			return $res[0];
}

    public function servicelist(Request $request){
                
                $input = $request->all();	

                $latitude = $input['latitude'];
								$longitude = $input['longitude'];
								
								$banner = Banners::all();	

								if($request->has('currency') && $request->input('currency')!='')
								{
								$currency_id = $request->input('currency');
								$exchangerate = $this->exchangerate($currency_id);
								$exchangerate['currency']=$currency_id;
								}
								else $exchangerate = array();

                if(!empty($input)){  

							  
									
                      $vendors_count = User::selectRaw('*, ( 6367 * acos( cos( radians( ? ) ) * cos( radians( `lat` ) ) * cos( radians( `long` ) - radians( ? ) ) + sin( radians( ? ) ) * sin( radians( lat ) ) ) ) AS distance', [$latitude, $longitude, $latitude])->where('admin','2')
					    ->having('distance', '<', \Config::get('constants.service_radius'))
							->get()->count();
									

							if($vendors_count==0){
								$result = array(
									"statusCode" => 200,  // $this-> successStatus
									"message" => "No Vendor found",
									"data" => array('services'=>array(), 'banners' => $banner , "commonly_ordered" => (object)array()),
										"exchangerate" => $exchangerate
								);
								return response()->json($result ); 
							}
							else{

								
								

								
								$services = Service::all();
		//$products = Products::all();
		$service_new =  array();
		foreach($services as $service){			
			$service['image'] = url('/').'/img/icons/32/database.png';


			$products_arr=array();
			$Products =Products::where('service_id','=',$service['id'])->get();
            $subcategories = Subservices::where('category',$service['id'])->get();
            $service['subcategories'] = $subcategories;

			foreach($service['products'] as $item){
				unset($item['qty']);
        $products_arr[] = $item['service_name']=$service['name'];
        $products_arr[] = $item['image']=url('/').'/img/uploads/'.$item['image'];
         $products_arr[] = $item['featured']=($item['featured']=='1')?1:0;
			}
			$service['products']= $products_arr;
			

			array_push($service_new, $service);
		}

		/* Get highest orderd items */
        $mostly_orderd = DB::table('order_product')
        ->select('order_id', DB::raw('COUNT(id) as orderd_times'))
        ->groupBy('order_id')
        ->orderBy(DB::raw('COUNT(id)'), 'DESC')
        ->take(10)
        ->get()->toArray();

       
        $products_array = [];
        foreach($mostly_orderd as $most_orderd)
        {
         $products_array[] = $most_orderd->order_id;
        }
        
       $mostly_ordered = Products::whereIn('id',$products_array)->get();
      $most_orderd_items = array();
      if(!$mostly_ordered->isEmpty())
      {
       foreach($mostly_ordered as $most_orderd)
       {
       	   unset($most_orderd['qty']);
       	   $most_orderd['image'] = url('/').'/img/uploads/'.$most_orderd['image'];
           $most_orderd_items[] = $most_orderd;
            
       }
   }

		$result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "success",
					"data" => array('services' => $service_new, 'banners' => $banner, "commonly_ordered" => $most_orderd_items),
					"exchangerate" => $exchangerate,
					
				);
							}
							


				          	

                  }
                  else{

					        	$result = array(
											"statusCode" => 200,  // $this-> successStatus
											"message" => "No Vendor found",
											"data" => array('services'=>array(), 'banners' => $banner , "commonly_ordered" => (object)array()),
											"exchangerate" => $exchangerate,
											
										);	


                  }

                                  
			                
			   
				

			return response()->json($result);

 }
    
    public function homebaners() 
    {  
		
         $banner = Banners::all(); 
		 $result = array(
			"statusCode" => 200,  // $this-> successStatus
			"message" => "success",
			/*"data" => array(
				'title'=>"MrNice",
				'description'=>"MrNice description",
				'link'=>"http://yapapp.net",
				'src'=>"http://hobyclean.mastishakmitr.com/img/slider/banner1.jpg"
				)*/
				"data" => $banner

		);
			
	
		return response()->json($result);
		}
		
		public function currencies()
    {
       
        $currencies = currencies::all(); 
        $result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "success",
					"data" => $currencies
		
				);
					
			
				return response()->json($result);
		}


		public function getAddressesApi()
    {
			$user = Auth::user(); 

						if ($user['is_activated']==0) {
							$result = array(
								"statusCode" => 707,  // $this-> successStatus
								"message" => "You are not active user.",
								 
								);
							return response()->json($result );            
						}
			
						if ($user['email_verified']==0) {
							$result = array(
								"statusCode" => 708,  // $this-> successStatus
								"message" => "Verify Your Email First.",
								 
								);
							return response()->json($result );            
						}

				$addresses = Address::where('user_id' , '=', $user->id)->get();
 
				if(!empty($addresses)){
					$result = array(
						"statusCode" => 200,  // $this-> successStatus
						"message" => "success",
						"data" => $addresses
						
	
					);
					
				}
				else{
					$result = array(
						"statusCode" => 200,  // $this-> successStatus
						"message" => "No address found",
						
						
	
					);
					
				}
				
				
            return response()->json($result); 
		}
		
		public function addAddressApi(Request $request)
    {
			$user = Auth::user(); 

						if ($user['is_activated']==0) {
							$result = array(
								"statusCode" => 707,  // $this-> successStatus
								"message" => "You are not active user.",
								 
								);
							return response()->json($result );            
						}
			
						if ($user['email_verified']==0) {
							$result = array(
								"statusCode" => 708,  // $this-> successStatus
								"message" => "Verify Your Email First.",
								 
								);
							return response()->json($result );            
						}

						$messages = array(
							'phoneno.required' => 'Phone No. is required.',
							'phoneno.numeric' => 'Phone No. must be numeric.',
							'phoneno.digits' => 'Phone No. must be between 6 to 15 digits.'
					);

						$validator = Validator::make($request->all(), [ 
							//'email' => 'email',
              'phoneno' => 'required|numeric|digits_between:6,15'
              //'postcode' => 'numeric|min:4'
						], $messages);

						if ($validator->fails()) { 
							$errors = $validator->errors()->all();
									$result = array(
										"statusCode" => 401,  // $this-> successStatus
										"message" => $errors[0],
										
									);
									return response()->json($result );            
								}
								

						$request['user_id'] = $user->id;

					$res =	Auth::user()->address()->create($request->all());
 
				if($res){
					$result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "success",
					"data" => $res
					

				);
			}
				else{
					$result = array(
					"statusCode" => 401,  // $this-> successStatus
					"message" => "error",
					
				);
					
					
				}
				
				
            return response()->json($result); 
		}

		public function deleteAddressApi(Request $request)
    {
			$user = Auth::user(); 

						if ($user['is_activated']==0) {
							$result = array(
								"statusCode" => 707,  // $this-> successStatus
								"message" => "You are not active user.",
								 
								);
							return response()->json($result );            
						}
			
						if ($user['email_verified']==0) {
							$result = array(
								"statusCode" => 708,  // $this-> successStatus
								"message" => "Verify Your Email First.",
								 
								);
							return response()->json($result );            
						}
				
					if(!$request->has('address_id') || $request->input('address_id')==''){
						$result = array(
							"statusCode" => 401,  // $this-> successStatus
							"message" => "address_id is required",
							
						);
						return response()->json($result); 
					}
        $destroy = Address::destroy($request->input('address_id'));
   
 
				if($destroy){
					$result = array(
						"statusCode" => 200,  // $this-> successStatus
						"message" => "success",
						"data" =>  (object) array()
						
	
					);
					
				}
				else{
					$result = array(
						"statusCode" => 401,  // $this-> successStatus
						"message" => "error",
						
						
	
					);
					
				}
				
				
            return response()->json($result); 
 
		}
		
		public function ordersApi(Request $request)
    {
        $user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
        }
        
        $type = $request->input('type');

        //0-unassigned, 1-assigned, 2- paid, 3,pickedup,4- delivered

        if($type=='unassign')
        {
            $orders=Orders::where('status','0')->where('user_id',$user->id)->get();

        } elseif ($type=='assign')
        {
            $orders=Orders::where('status','1')->where('user_id',$user->id)->get();

        }
        elseif ($type=='pending')
        {
            $orders=Orders::whereIn('status', array(2, 3))->where('user_id',$user->id)->get();

        }
        elseif ($type=='delivered')
        {
            $orders=Orders::where('status','4')->where('user_id',$user->id)->get();

        } else{

            $orders = Orders::where('user_id',$user->id)->get();
        }
        
        foreach($orders as $key=>$order){
            $orders[$key]['shippingaddress'] = Address::find($order->shipping_address);
        }


				if($request->has('currency') && $request->input('currency')!='')
								{
								$currency_id = $request->input('currency');
								$exchangerate = $this->exchangerate($currency_id);
								$exchangerate['currency']=$currency_id;
								}
								else $exchangerate = array();
								
        $result = array(
			"statusCode" => 200, 
			"message" => "success",
			"data" => $orders,
			"exchangerate" => $exchangerate

        );
        
        return response()->json($result);
		}
		

		public function getorderApi(Request $request)
    {
        $user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}
				
				if(!$request->has('order_id') || $request->input('order_id')==''){
					$result = array(
						"statusCode" => 401,  // $this-> successStatus
						"message" => "order_id is required",
						 
						);
				return response()->json($result ); 
				}
        
        $order_id = $request->input('order_id');

        //0-unassigned, 1-assigned, 2- paid, 3,pickedup,4- delivered

        

            $order = Orders::all()->find($order_id);
       
						$order['shippingaddress'] = Address::find($order->shipping_address);
						$order['orderitems'] = DB::table('order_product')->select('order_product.*','products.name','products.price')->join('products','order_product.order_id','=','products.id')->where('order_product.product_id',$order->id)->get();

						if(!empty($order->assigned_to)){
								$vendor_detail = User::find($order->assigned_to);
        
			    $order['vendor_detail'] = ['name' =>$vendor_detail->name,'email' =>$vendor_detail->email , 'address' => $vendor_detail->address , 'phone' => $vendor_detail->phone,'image'=>url('/').'/images/profile/'.$vendor_detail->id.'/'.$vendor_detail->image];

						}
						else{

							$order['vendor_detail'] = (object)[];
						}
					
						
			    //$order['service_type'] = round(UsersController::calculateExpress($order['service_type'],$order['total']),2);
			     $order['service_charges'] = round(UsersController::calculateExpress($order['service_type'],$order['total']),2);
			    $order['vat'] = round((\Config::get('constants.vat')/100)*$order['total'],2);
			    $order['gateway_charges'] = round((\Config::get('constants.payment_gateway_fee')/100)*(($order['shipping_charges']+$order['total']+ $order['service_charges']+ $order['vat'])),2);
				$currency_id = $order->currency;
				$exchangerate['currency']=(string)$currency_id;
				$exchangerate['exchange_rate']=(string)$order->conversion_rate;
				$currencies_data = currencies::find($currency_id);
				$exchangerate['code'] = $currencies_data->code;
				$payment = dpoPayments::where('order_id',$order['id'])->first();
				if(!empty($payment))
				{


					$order['payment_status'] = UsersController::paymentStatus($payment->payment_status);
				}
				else{
					if($order['payment_method'] == 1 && $order['status']== 7 ):
					$order['payment_status'] = 3;
					else:
                    $order['payment_status'] = 1;
					endif;
				}

				

        $result = array(
			"statusCode" => 200, 
			"message" => "success",
			"data" => $order,
			"exchangerate" => $exchangerate

        );
        
        return response()->json($result);
		}
		
		public function ordersreceived($type='')
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}

         //0-unassigned, 1-assigned, 2-accepted, 3- paid, 4-pickedup, 5-Order processed, 6-out for delivery 7- delivered, 8-cancelled by customer, 9-rejected by customer, 902-rejected by customer again, 903- rejected by customer 3rd time, 102-assigned again, 103-assigned 3rd time

          $orders = Orders::whereNotIn('status', array(0,9, 902,903,8,1,102,103))->where('assigned_to',$user->id)->get();
      
        //print_r($orders);
        foreach($orders as $key=>$order){
						
						$currencies_data = currencies::find($order->currency);
						$orders[$key]['code'] = $currencies_data->code;
						$orders[$key]['exchange_rate'] = $currencies_data->exchange_rate;

						$orders[$key]['shippingaddress'] = Address::find($order->shipping_address);
						$order['orderitems'] = DB::table('order_product')->select('order_product.*','products.name','products.price')->join('products','order_product.order_id','=','products.id')->where('order_product.product_id',$order->id)->get();

				}
				
				$result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => $orders
		
						);
						
						return response()->json($result);


		}
		
		public function updateorderstatus(Request $request)
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}
				if ($user['admin']!=0) {
					$result = array(
							"statusCode" => 401,  // $this-> successStatus
							"message" => "You are not authorised to take this action.",
							 
							);
					return response()->json($result );            
			}

				$input = $request->all();	

        $order_id = $input['order_id'];
				$status = $input['status'];


				if(!$request->has('order_id') || $request->input('order_id')==''){
					$result = array(
							"statusCode" => 401,  
							"message" => "order_id is mandetory.",
							 
							);
					return response()->json($result );            
			}
			if(!$request->has('status') || $request->input('status')==''){
				$result = array(
						"statusCode" => 401,  
						"message" => "status is mandetory.",
						 
						);
				return response()->json($result );            
		  }

			$status_allowed = array('2','9','902','903');
			if (!in_array($status, $status_allowed)) {
        $result = array(
					"statusCode" => 401,  
					"message" => "invalid status",
					 
					);
		  	return response()->json($result ); 
			
			}

			$order = Orders::find($order_id);
			
			if($status=='9'){
        if($order->status==1) $status=9; 
        elseif($order->status==102) $status=902;
        elseif($order->status==103) $status=903; 
			}
			
			if($input['status']=='2'){
				$order_data = Orders::select('assigned_to')->where('id', $order_id)->get();
				$user_id = $order_data[0]->assigned_to;
				$receiver_user_type = '2';
				$order_url = "/vendororderdetail/$order_id";
				$user_data = User::find($user_id);
				$fcm_token = $user_data['fcm_token'];
				$title = "New Order Received";
				$message = "New order #$order_id has been assigned to you";  
        $mail_subject = "MrNice - New Order #$order_id Assigned";
				$result['noti_res'] = notificationController::sendPushNotification($fcm_token, $title, $message, $user_id, $receiver_user_type, $order_id);

				    $user_data->mail_subject = $mail_subject;
            $user_data->message = $message;
            $user_data->order_url = $order_url;
            $user_data->notify(new OrderAlert($user_data));
		}

				
        Orders::where('id', $order_id)->update([
            'status'=>$status
        ]);
        DB::table('order_tracking')->insert(
            ['order_id' => $order_id, 'order_status' => $status]
        );

        $result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => "Order status has been updated successfully!"
		
						);
						
						return response()->json($result);
		}
		
		public function trackorder(Request $request)
    {
			$user = Auth::user();
			if ($user['is_activated']==0) {
					$result = array(
							"statusCode" => 707,  // $this-> successStatus
							"message" => "You are not active user.",
							 
							);
					return response()->json($result );            
			}

			if ($user['email_verified']==0) {
					$result = array(
							"statusCode" => 708,  // $this-> successStatus
							"message" => "Verify Your Email First.",
							 
							);
					return response()->json($result );            
			}
			$input = $request->all();	

			$order_id = $input['order_id'];


			if(!$request->has('order_id') || $request->input('order_id')==''){
				$result = array(
						"statusCode" => 401,  
						"message" => "order_id is mandetory.",
						 
						);
				return response()->json($result );            
		}
		
		//0-unassigned, 1-assigned, 2-accepted, 3- paid, 4-pickedup, 5-Order processed, 6-out for delivery 7- delivered, 8-cancelled by customer, 9-rejected by customer, 902-rejected by customer again, 903- rejected by customer 3rd time, 102-assigned again, 103-assigned 3rd time

		$ordertracking = DB::table('order_tracking')->where('order_id',$order_id)->whereIn('order_status',array(0,4,5,6,7))->get();

		$result = array(
			"statusCode" => 200, 
			"message" => "success",
			"data" => $ordertracking

				);
				
				return response()->json($result);
		}

		public function updateorderstatusbyvendor(Request $request)
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}
        

				$input = $request->all();	

        $order_id = $input['order_id'];
				$status = $input['status'];
				$order = Orders::find($order_id);

				if ($user['admin']!=2 || $user['id']!=$order->assigned_to) {
					$result = array(
							"statusCode" => 401,  // $this-> successStatus
							"message" => "You are not authorised to take this action.",
							 
							);
					return response()->json($result );            
			}


				if(!$request->has('order_id') || $request->input('order_id')==''){
					$result = array(
							"statusCode" => 401,  
							"message" => "order_id is mandetory.",
							 
							);
					return response()->json($result );            
			}
			if(!$request->has('status') || $request->input('status')==''){
				$result = array(
						"statusCode" => 401,  
						"message" => "status is mandetory.",
						 
						);
				return response()->json($result );            
		  }

			//0-unassigned, 1-assigned, 2-accepted, 3- paid, 4-pickedup, 5-Order processed, 6-out for delivery 7- delivered, 8-cancelled by customer, 9-rejected by customer, 902-rejected by customer again, 903- rejected by customer 3rd time, 102-assigned again, 103-assigned 3rd time
			//3- paid, 4-pickedup, 5-Order in process, 6-out for delivery 7- delivered

			$status_allowed = array('3','4','5','6','7');
			if (!in_array($status, $status_allowed)) {
        $result = array(
					"statusCode" => 401,  
					"message" => "invalid status",
					 
					);
		  	return response()->json($result ); 
			
			}

			
			
			if($status=='9'){
        if($order->status==1) $status=9; 
        elseif($order->status==102) $status=902;
        elseif($order->status==103) $status=903; 
			}


				$order_data = Orders::select('user_id')->where('id', $order_id)->get();
        $user_id = $order_data[0]->user_id;
				$receiver_user_type = '0';
				$order_url = "/listorders";
				$user_data = User::find($user_id);
		    $fcm_token = $user_data['fcm_token'];
		

			if($status=='3'){
					$title = "Order Paid";
					$message = "Payment of your order #$order_id has been received"; 
					$mail_subject = "MrNice - Order #$order_id Paid";
			}
			else if($status=='4'){
					$title = "Order Picked Up";
					$message = "Your order #$order_id has been picked to be processed";  
					$mail_subject = "MrNice - Order #$order_id Picked Up";
			}
			else if($status=='5'){
					$title = "Order In Process";
					$message = "Your order #$order_id is in process";  
					$mail_subject = "MrNice - Order #$order_id In Process";
			}
			else if($status=='6'){
					$title = "Order Out For Delivery";
					$message = "Your order #$order_id is out for delivery to your door";  
					$mail_subject = "MrNice - Order #$order_id Out For Delivery";
			}
			else if($status=='7'){
					$title = "Order Delivered";
					$message = "Your order #$order_id has been delivered to your door";  
					$mail_subject = "MrNice - Order #$order_id Delivered";
					
					$points_rate = \Config::get('constants.points_rate');
            $amount = $order_data[0]->sub_total*$points_rate;
            $reward_msg = "Order #$order_id Paid";
            $data = [
              'ref_id' => $order_id,
            ];
            $transaction = $user_data->addPoints($amount,$reward_msg,$data);
			}

	   if($title){
		  	$noti_res = notificationController::sendPushNotification($fcm_token, $title, $message, $user_id, $receiver_user_type, $order_id);
				$user_data->mail_subject = $mail_subject;
        $user_data->message = $message;
        $user_data->order_url = $order_url;
        $user_data->notify(new OrderAlert($user_data));
	   }
			

				
        Orders::where('id', $order_id)->update([
            'status'=>$status
        ]);
        DB::table('order_tracking')->insert(
            ['order_id' => $order_id, 'order_status' => $status]
        );

        $result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => "Order status has been updated successfully!",
					"noti_res" => $noti_res
		
						);
						
						return response()->json($result);
		}

		public function updatedevicetoken(Request $request)
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}

				$error="";

				if(!$request->has('fcm_token') || $request->input('fcm_token')==''){
					$error = "Field fcm_token is mandetory";
				}
	
				if(!$request->has('device_type') || $request->input('device_type')==''){
					$error = "Field device_type is mandetory";
				}
	
				if($error!=""){
					$result = array(
						"statusCode" => 401,  // $this-> successStatus
						"message" => $error,
						 
						);
					return response()->json($result ); 
				}
        
				$user->fill([
					'fcm_token' => $request->input('fcm_token'),
					'device_type' => $request->input('device_type')
				]);

				if($user->save()){
				$result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => $user
		
						);
					}
					else{
						$result = array(
							"statusCode" => 401,  // $this-> successStatus
							"message" => "error in updating",
							
							);
					}
						
						return response()->json($result);
		}

		public function notifications()
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}

         
          $Notification = DB::table('notification')->where('user_id',$user->id)->orderBy('id', 'DESC')->get();
      
				 $result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => $Notification
		
						);
						
						return response()->json($result);


		}

		public function notificationread(Request $request)
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}

				if(!$request->has('notification_id') || $request->input('notification_id')==''){
					$result = array(
						"statusCode" => 401,  // $this-> successStatus
						"message" => "notification_id is required",
						
					);
					return response()->json($result); 
				}

         
          DB::table('notification')->where('id',$request->input('notification_id'))->update([
						'read'=>1
				]);
      
				 $result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => 'Updated successfully'
		
						);
						
						return response()->json($result);


		}

		public function rateorder(Request $request)
    {
			$user = Auth::user();
        if ($user['is_activated']==0) {
            $result = array(
                "statusCode" => 707,  // $this-> successStatus
                "message" => "You are not active user.",
                 
                );
            return response()->json($result );            
        }

        if ($user['email_verified']==0) {
            $result = array(
                "statusCode" => 708,  // $this-> successStatus
                "message" => "Verify Your Email First.",
                 
                );
            return response()->json($result );            
				}

				if(!$request->has('order_id') || $request->input('order_id')==''){
					$result = array(
						"statusCode" => 401,  // $this-> successStatus
						"message" => "order_id is required",
						
					);
					return response()->json($result); 
				}

				if(!$request->has('rating') || $request->input('rating')==''){
					$result = array(
						"statusCode" => 401,  // $this-> successStatus
						"message" => "rating is required",
						
					);
					return response()->json($result); 
				}

				$rating = $request->input('rating');
        $feedback = $request->input('feedback');
        $order_id = $request->input('order_id');

				$rating_allowed = array('1','2','3','4','5');
				if (!in_array($rating, $rating_allowed)) {
					$result = array(
						"statusCode" => 401,  
						"message" => "invalid rating",
						 
						);
					return response()->json($result ); 
				
				}

         
				
        
        Orders::where('id', $order_id)->update([
            'rating'=>$rating,
            'feedback'=>$feedback
        ]);	$rating = $request->input('rating');
        $feedback = $request->input('feedback');
        $order_id = $request->input('order_id');
      
				 $result = array(
					"statusCode" => 200, 
					"message" => "success",
					"data" => 'Updated successfully'
		
						);
						
						return response()->json($result);


		}




    /* get subservices */

    function getSubServices(Request $request)
    {
    	$input = $request->all();
       if(!empty($input)){  

      $services = Subservices::where('category',$input['parent'])->get();
		if(!empty($services))
		{

        $result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "success",
					"data" => array('sub_service' => $services)
				);

		       }

          else{

              $result = array(
					"statusCode" => 200,  // $this-> successStatus
					"message" => "nothing found",
					"data" => array('sub_service' => array())
				);

                }

		
				}
							

                  else{

					 $result = array(
											"statusCode" => 200,  // $this-> successStatus
											"message" => "No Vendor found",
											"data" => array('services'=>array())
											
										);	


                  }

                                  
			                
			   
				

			return response()->json($result);

           }

		    /* search in sub services */

		    function searchSubservices(Request $request)
		    {
		    
		    $input = $request->all();
		    if(!empty($input))
		    {
		    $products =  Products::select('*')->where('service_id',$input['parent_category'])
		    ->when(!empty($input['category']) , function ($query) use($input){
		   return $query->where('subcat_id',$input['category']);
		   })
		   ->when (!empty($input['product']) , function ($query) use($input){
		   return $query->where('name','like', '%'.$input['product'].'%');
		   })->get();


		    if(!empty($products))
		    {
		     $result = array(
							"statusCode" => 200,  // $this-> successStatus
							"message" => "success",
							"data" => array('products' => $products)
					
						);

					    }
					    else{
					   $result = array(
										"statusCode" => 200,  // $this-> successStatus
										"message" => "nothing found",
										"data" => array('products' => array())
								
									);

					    }
					   

		   			}


								   else{
								$result = array(
													"statusCode" => 200,  // $this-> successStatus
													"message" => "No Vendor found",
													"data" => array('products'=>array())
												);	


		   }
			return response()->json($result);
		    }

      /* vendor earnings  */
     
      function vendorEarnings(Request $request)
      {
           $user = Auth::user();

          if ($user['admin']!=2) {
					$result = array(
							"statusCode" => 401,  // $this-> successStatus
							"message" => "You are not authorised to take this action.",
							 
							);
					return response()->json($result );            
			}

      	$total_earned = Orders::where('status',7)->where('assigned_to',Auth::user()->id)->get();
        $pending_earnings = Orders::whereIn('status',[2,3,4,5,6])->where('assigned_to',Auth::user()->id)->get();

        $total_earned_output = array();
        $pending_earned_output = array();
       $total_earn = 0;
       $pending_earn = 0;
       if(!empty($total_earned))
       {
        foreach($total_earned as $earned)
        {
           $earned->sub_total = CurrencyController::convertUsd($earned->currency,$earned->sub_total);
           $total_earn += $earned->sub_total;

           $earned = array('order_id' => $earned->id , 'customer_name' => userName($earned->user_id)->name, 'subtotal' => ($earned->sub_total-((\Config::get('constants.admin_commissin_percent')/100)*$earned->sub_total)));
           array_push($total_earned_output,$earned);
        }
       }

       if(!empty($pending_earnings))
       {

        foreach($pending_earnings as $pending)
        {
           $pending->sub_total = CurrencyController::convertUsd($pending->currency,$pending->sub_total);
           $pending_earn += $pending->sub_total;
            $pending = array('order_id' => $pending->id , 'customer_name' => userName($pending->user_id)->name, 'subtotal' => ($pending->sub_total-((\Config::get('constants.admin_commissin_percent')/100)*$pending->sub_total)));
           array_push($pending_earned_output,$pending);
        }
       }

      if(!empty($total_earned) || !empty($pending_earnings))
      {
      $total_earn	= $total_earn - ((\Config::get('constants.admin_commissin_percent')/100)*$total_earn);
       $pending_earn =  $pending_earn - ((\Config::get('constants.admin_commissin_percent')/100)*$pending_earn);
      	$result = array(
							"statusCode" => 200,  // $this-> successStatus
							"message" => "success",
							"data" => array('total_earned' => $total_earned_output , 'pending_earnings' =>$pending_earned_output , 'total_earned_count' =>$total_earn , 'pending_count' => $pending_earn));

      }
      else{
      	$result = array(
							"statusCode" => 200,  // $this-> successStatus
							"message" => "No Earning found",
							"data" => array('total_earned' => [] , 'pending_earnings' =>[] , 'total_count' =>0 , 'pending_earned_count' => 0));
      }

      return response()->json($result);

      }


      /* End Vendor earnings */

      /* Vendor reviews */

      function vendorReviews(Request $request)
      {

      	 $user = Auth::user();

          if ($user['admin']!=2) {
					$result = array(
							"statusCode" => 401,  // $this-> successStatus
							"message" => "You are not authorised to take this action.",
							 
							);
			return response()->json($result );            
			}

      	$total_rating = Orders::where('rating','!=','0')->where('assigned_to',Auth::user()->id)->sum('rating');
        $reviews_count = Orders::where('feedback','!=',null)->where('assigned_to',Auth::user()->id)->count();
        $reviews = Orders::where('feedback','!=',null)->where('assigned_to',Auth::user()->id)->get();
        $all_reviews = [];

        foreach($reviews as $review)
        {
        	$output = array('order_id' => $review['id'],'user_name'=> userName($review['user_id'])->name,'comment' => $review['feedback'],'rating' => $review['rating']);
        	array_push($all_reviews,$output);
        }

       if(!empty($total_rating))
       {
       $result = array(
							"statusCode" => 200,  // $this-> successStatus
							"message" => "success",
							"data" => array('total_rating' => $total_rating , 'reviews_count' =>$reviews_count , 'reviews' =>$all_reviews));

       }
       else
       {
       	$result = array(
							"statusCode" => 200,  // $this-> successStatus
							"message" => "No Reviews Found",
							"data" => array('total_rating' => 0 , 'reviews_count' =>0 , 'reviews' =>[]));

       }
           
     return response()->json($result);


      }



      /* Contact api */

      function contactUs(Request $request)
      {
      	$validator = Validator::make($request->all(), [ 
             'name' => 'required|min:2',
            'subject' => 'required',
            'email' => 'required|email',
            'message' => 'required'
      	]);
      	if ($validator->fails()) { 
			$errors = $validator->errors()->all();
			$result = array(
						"statusCode" => 401,  // $this-> successStatus
						"message" => $errors[0],
						
					);
					return response()->json($result ); 

		}
		else{
			 ContactUS::create($request->all());

            $mail_data = User::find(\Config::get('constants.admin_user_id'));
            
            $mail_data->user_subject = $request->input('subject');
            $mail_data->user_name = $request->input('name');
            $mail_data->user_email = $request->input('email');
            $mail_data->user_message = $request->message;
            $notification =  $mail_data->notify(new ContactUsNoti($mail_data));
            $result = array(
						"statusCode" => 200,  // $this-> successStatus
						"message" => 'successfully sent',
						
					);
            
            return response()->json($result ); 
		}

      }

		    /* Calculate express shipping */

    public static function calculateExpress($type,$total)
    {
    
    switch($type)
    {

    case "2":
    return ((50/100)*$total);
    break;

    case "3":
    return ((40/100)*$total);
    break;

    case "4":
    return ((30/100)*$total);
    break;

    case "5":
    return ((20/100)*$total);
    break;

    default:
    return 0;
    break;

    }

    }

   /* get payment status */

   public static function paymentStatus($status)
   {

   	/* switch($status)
   	{
       case "0":
       return 2;
       break;

       case "1":
       return 3;
       break;
       case "2":
       return 0;
       break;
  
   	} */


   		switch($status)
   	{
       case "0":
       return 1;
       break;

       case "1":
       return 3;
       break;
       case "2":
       return 0;
       break;
  
   	}

   }


   public function categoryList() {
        
	$res = category::all();
	$result = array(
		"statusCode" => 200,  // $this-> successStatus
		"message" => "success",
		"data" => $res
	);

	return response()->json($result); 
}


public function nearByShops(Request $request) {

	$error = "";
	if(!$request->has('lat') || $request->input('lat') == ''){
		$error = "lat is mandatory";
	}
	if(!$request->has('long') || $request->input('long') == ''){
		$error = "long is mandatory";
	}
	if($error != "") {
		$result = array(
			"statusCode" => 401,  // $this-> successStatus
			"message" => $error	
		);
		return response()->json($result ); 
	}

	$input = $request->all();	

	$latitude = $input['lat'];
	$longitude = $input['long'];

	$res = Shop::selectRaw('*, ( 6367 * acos( cos( radians( ? ) ) * cos( radians( `lat` ) ) * cos( radians( `long` ) - radians( ? ) ) + sin( radians( ? ) ) * sin( radians( lat ) ) ) ) AS distance', [$latitude, $longitude, $latitude])
	->having('distance', '<', \Config::get('constants.service_radius'))
		->get();

	$result = array(
		"statusCode" => 200,  // $this-> successStatus
		"message" => "success",
		"data" => $res
	);

	return response()->json($result); 
}


public function shopDetails(Request $request) {

	$error = "";
	if(!$request->has('shop_id') || $request->input('shop_id') == ''){
		$error = "shop_id is mandatory";
	}
	if($error != "") {
		$result = array(
			"statusCode" => 401,  // $this-> successStatus
			"message" => $error	
		);
		return response()->json($result ); 
	}

	$input = $request->all();	

	$shop_id = $input['shop_id'];

	$res = Shop::find($shop_id);

	$result = array(
		"statusCode" => 200,  // $this-> successStatus
		"message" => "success",
		"data" => $res
	);

	return response()->json($result); 
}

    
     
}

