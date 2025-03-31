<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\Hasfactory;

class Files extends Model
{
    use HasFactory;
    protected $fillable = ['name','route'];
}