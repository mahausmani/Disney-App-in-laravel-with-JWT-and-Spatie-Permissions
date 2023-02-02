<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Character extends Model
{
    use HasFactory;
    public $timestamps = false;
    // protected $guard_name = 'admin';
    protected $fillable = [
        'name'
    ];
    protected $casts = [
    ];
    
    public function votedBy()
    {
        return $this->belongsToMany(User::class, 'votes', 'character_id', 'user_id');
    }
}
