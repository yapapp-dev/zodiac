<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    protected $table  = 'products';
    protected $primarykey = 'id';

    protected $guarded = [];
}
