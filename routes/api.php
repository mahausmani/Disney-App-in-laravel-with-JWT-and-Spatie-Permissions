<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;
use App\Http\Controllers\RoleController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\CharacterController;

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

 
//register user
Route::post('/register',  [AuthController::class, 'register']);
Route::post('login',  [AuthController::class, 'login'])->name('login');
Route::middleware("api")->group(function(){
        Route::post('/character/create',  [CharacterController::class, 'create']);
        Route::get('/show-all-characters',  [CharacterController::class, 'view']);
        Route::post('/character/update{id}',  [CharacterController::class, 'update']);
        Route::post('/character/delete{id}',  [CharacterController::class, 'delete']);
        Route::get('/vote/{characterId}',  [UserController::class, 'vote']);
        
 
        Route::get('/get-user/{id}',[UserController::class,'view_user']);
        Route::get('/show-all-users',[UserController::class,'view']);
        Route::post('/update-user/{id}',[UserController::class,'update']);
        Route::post('/delete-user/{id}',[UserController::class,'delete']);
        Route::post('/create-user',[UserController::class,'create']);

        Route::get('/show-all-roles',[RoleController::class,'view']);
        Route::post('/update-role/{id}',[RoleController::class,'update']);
        Route::get('/delete-role/{id}',[RoleController::class,'delete']);
        Route::post('/create-role',[RoleController::class,'create']);
        Route::get('/logout',[AuthController::class,'logout']);
});
