<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use App\Models\Character;
use App\Http\Resources\User as UserResource;
use App\Http\Resources\Character as CharacterResource;
use Illuminate\Support\Facades\Hash;
use Spatie\Permission\Models\Role;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Facades\JWTAuth\Exceptions;

use Spatie\Permission\Models\Permission;

class UserController extends Controller
{
    public function __construct__()
    {
        $this->middleware('auth:api');
    
    }
    
    public function update(Request $request ){
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is missing'], 401);
        }
        if (is_null($user) || !$user->can('user.update')) {
            abort(403, 'Sorry !! You are Unauthorized to update any user !');
        }
        $user = User::select('*')->where('id', $request->id)->first();
        $user->name = $request['name'];
        $user->email = $request['email'];
        $user->save();
        return $user;
    }
    
    public function view_user(Request $request){
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is missing'], 401);
        }
        if (is_null($this->user) || !$this->user->can('user.view_user')) {
            abort(403, 'Sorry !! You are Unauthorized to view any other user !');
        }
        $user = User::select('*')->where('id', $request->id)->first();
        return $user;
    }
    
    public function view(Request $request){
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token is missing'], 401);
        }
        
        if (is_null($user) || !$user->can('user.view')) {
            abort(405, 'Sorry !! You are Unauthorized to view any users!');
        }
        
        $users = User::all();
        return $users;
    }
    public function create(Request $request){
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
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);
        $user->save();
        $roles = $request->roles;
        $permissions = $request->input('permissions');
        for ($j = 0;$j<count($roles);$j++){
            $role = Role::findByName($roles[$j]);
            $user->assignRole($role);
            for($i = 0;$i<count($role->permissions);$i++){
                $permission = $role->permissions[$i];
                $user->givePermissionTo($permission);
            }
        }
        //for extra permissions
        if($permissions){
            for ($i = 0; $i < count($permissions); $i++) {
                $permission = $permissions[$i];
                $user->givePermissionTo($permission);
            }
        }
        return UserResource::make($user)->response();
    }

    public function delete(Request $request,int $id){
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
        if (is_null($user) || !$user->can('user.delete')) {
            abort(403, 'Sorry !! You are U nauthorized to delete any user!');
        }

        if ($id === 1) {
            return "error, Sorry !! You are not authorized to delete this user!";
        }

        $user = User::select('*')->where('id', $request->id)->first();
        if (!is_null($user)) {
            $user->delete();
        }

        
        return "success, User has been deleted !";
    }
    public function vote(int $characterId): JsonResponse
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
        if (is_null($user) || !$user->can('character.vote')) {
            abort(403, 'Sorry !! You are Unauthorized to vote for any character!');
        }
        $user->voteCharacter()->attach($characterId);
        return "vote has been casted";
    }

}
