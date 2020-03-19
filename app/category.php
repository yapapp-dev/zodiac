<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class category extends Model
{
    protected $table  = 'category';
    protected $primarykey = 'id';
    protected $fillable = [
        'name', 'parent'
    ];
}
