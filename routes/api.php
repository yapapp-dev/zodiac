<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});


Route::group(['namespace' => 'Api', 'as' => 'api'], function () { 

    Route::get('/user', function (Request $request) { 
        return $request->user();
    })->middleware('auth:api');

    Route::post('login', 'UsersController@login');
    Route::post('register', 'UsersController@register');
    Route::post('verifyOtp', 'UsersController@verifyOtp');
    Route::post('verifyUser', 'UsersController@verifyUser');
    Route::get('send-otp/{id}', 'UsersController@sendOtp');
    Route::post('sociallogin','UsersController@sociallogin');
    Route::post('logout', 'UsersController@logout'); 

    Route::post('forgotPassword', 'UsersController@forgotPassword');
    Route::post('resetPassword', 'UsersController@resetPassword');

    Route::post('changePassword', 'UsersController@changePassword');
    // Route::post('servicelist', 'UsersController@servicelist'); 
    // Route::post('subservice', 'UsersController@getSubServices'); 
    // Route::post('search-service', 'UsersController@searchSubservices');
    // Route::post('servicelistvendor', 'UsersController@servicelistvendor'); 
    // Route::get('homebaners', 'UsersController@homebaners'); 
    // Route::get('currencies', 'UsersController@currencies');  
    // Route::get('sendPushNotification','notificationController@sendPushNotificationApi');

    Route::group(['middleware' => ['auth:api', 'logs']], function(){
        Route::get('logout', 'UsersController@logout');
        Route::post('updateprofile', 'UsersController@updateprofile');
        
    });

    Route::get('userdetails', 'UsersController@details');
    Route::get('categoryList', 'UsersController@categoryList');

    Route::post('addProduct', 'ProductsController@addProduct');

});
