<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class NewType extends Model
{
    use HasFactory;
    //=========IMPORTANTE ADAPTAR AL MODELO=============
  // Define la clave primaria personalizada
  protected $primaryKey = 'new_typ_id';

  // Define los atributos que se pueden asignar en masa
  protected $fillable = [
      'new_typ_name',
  ];

  // Indica que el modelo no utiliza marcas de tiempo
  public $timestamps = false;
}
