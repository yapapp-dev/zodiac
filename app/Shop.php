<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Shop extends Model
{
    protected $table  = 'shops';
    protected $primarykey = 'id';
    protected $fillable = [
        'name', 'email', 'image', 'address', 'phone', 'active', 'created_at', 'updated_at', 'lat', 'long'
    ];
}
