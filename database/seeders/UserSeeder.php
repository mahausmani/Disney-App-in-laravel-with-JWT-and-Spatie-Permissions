<?php

namespace Database\Seeders;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
class UserSeeder extends Seeder
{
    
    public function run()
    {
        /**
     * Run the database seeds.
     *
     * @return void
     */
        $user = User::where('name', 'superadmin')->first();

        if (is_null($user)) {
            $user           = new User();
            $user->name     = "Super Admin";
            $user->email    = "superadmin@example.com";
            $user->password = Hash::make('12345678');
            $user->save();
        }
    }
}
