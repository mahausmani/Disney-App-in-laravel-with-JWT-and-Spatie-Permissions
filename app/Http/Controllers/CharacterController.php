<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use App\Models\Character;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use App\Http\Resources\Character as CharacterResource;

class CharacterController extends Controller
{
  
    public function view()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is missing'], 401);
        }
        if (is_null($user) || !$user->can('user.create')) {
            abort(405, 'Sorry !! You are Unauthorized to create any users!');
        }
        if (is_null($user) || !$user->can('character.view')) {
            abort(405, 'Sorry !! You are Unauthorized to view any character!');
        }
        $characters = Character::get();
        return CharacterResource::collection($characters)->response();
    }
    
    public function create(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is missing'], 401);
        }
        if (is_null($user) || !$user->can('user.create')) {
            abort(405, 'Sorry !! You are Unauthorized to create any users!');
        }
        if (is_null($user) || !$user->can('character.create')) {
            abort(405, 'Sorry !! You are Unauthorized to create any character!');
        }
        $character = Character::create([
            'name' => $request->name,
        ]);
        return CharacterResource::make($character)->response();
    }

    
    public function update(Request $request){
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is missing'], 401);
        }
        if (is_null($user) || !$user->can('user.create')) {
            abort(405, 'Sorry !! You are Unauthorized to create any users!');
        }
        if (is_null($user) || !$user->can('role.update')) {
            abort(403, 'Sorry !! You are Unauthorized to edit any role !');
        }
        
        $character = Character::select('*')->where('id', $request->id)->first();
        if (!is_null($character) ){
            $character->name = $request->name;
            $character->save();
        }
        return CharacterResource::make($character)->response();
    }
    
    public function delete(Request $request){
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is missing'], 401);
        }
        if (is_null($user) || !$user->can('user.create')) {
            abort(405, 'Sorry !! You are Unauthorized to create any users!');
        }
        if (is_null($user) || !$user->can('character.delete')) {
            abort(403, 'Sorry !! You are Unauthorized to delete any character!');
        }

        $character = Character::select('*')->where('id', $request->id)->first();
        if (!is_null($character) ){
            $character->delete();
        }

        
        return "success, Character has been deleted !";
    }
    
}
