<?php
namespace Database\Seeders;
use App\Models\User;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class RolePermissionSeeder extends Seeder
{
    public function run()
    {
        $permissions = [

            [
                'group_name' => 'character',
                'permissions' => [
                    'character.view',
                    'character.update',
                    'character.create',
                    'character.delete',
                    'character.vote',
                ]
            ],
            [
                'group_name' => 'user',
                'permissions' => [
                    'user.view',
                    'user.view_user',
                    'user.update',
                    'user.delete',
                    'user.create',
                ] 
            ],
            [
                'group_name' => 'role',
                'permissions' => [
                    'role.create',
                    'role.view',
                    'role.update',
                    'role.delete',
                ]
            ],
            
        ];
        
        
        $roleSuperAdmin = Role::create(['name' => 'superadmin']);
        // , 'guard_name' => 'admin']);
        // Assign super admin role permission to superadmin user
        $user = User::where('name', 'Super Admin')->first();
        
        for ($i = 0; $i < count($permissions); $i++) {
            $permissionGroup = $permissions[$i]['group_name'];
            for ($j = 0; $j < count($permissions[$i]['permissions']); $j++) {
                $permission = Permission::create(['name' => $permissions[$i]['permissions'][$j], 'group_name' => $permissionGroup]);// 'guard_name' => 'admin',
                $roleSuperAdmin->givePermissionTo($permission);
                $permission->assignRole($roleSuperAdmin);
            }
        }
        
        for($i = 0;$i<count($roleSuperAdmin->permissions);$i++){
            $permission = $roleSuperAdmin->permissions[$i];
            $user->givePermissionTo($permission);
        }
        
        if ($user) {
            $user->assignRole($roleSuperAdmin);
        }
        
        $role = Role::create(['name' => 'user']);
        // , 'guard_name' => 'admin']);

            
        $permissions    = ['character.view','character.vote'];
        for($i = 0;$i<count($permissions);$i++){
            $role->givePermissionTo($permissions[$i]);
        }
    }
}
