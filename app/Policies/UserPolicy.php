<!-- <?php

namespace App\Policies;

use App\Models\User;
use App\Models\Role;
use Illuminate\Auth\Access\HandlesAuthorization;

class UserPolicy
{
    use HandlesAuthorization;

    $public ADMIN = 1;
    public function __construct()
    {
    }

    public function update(User $user)
    {
        foreach ($user->roles as $role)
        {
            if ($role->pivot->role_id == $ADMIN){
                return TRUE;
            }
        }
        return FALSE;
    }
    public function get_user(User $user)
    {
        foreach ($user->roles as $role)
        {
            if ($role->pivot->role_id == 1){
                return TRUE;
            }
        }
        return FALSE;
    }

    public function show_all_users(User $user)
    {
        foreach ($user->roles as $role)
        {
            if ($role->pivot->role_id == 1){
                return TRUE;
            }
        }
        return FALSE;
    }

    public function create_character(User $user)
    {
        foreach ($user->roles as $role)
        {
            if ($role->pivot->role_id == 1){
                return TRUE;
            }
        }
        return FALSE;
    }
} -->