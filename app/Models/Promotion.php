<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Promotion extends Model
{
    use HasFactory;

    // Nombre de la tabla asociada al modelo
    protected $table = 'promotions';

    // Define la clave primaria personalizada
    protected $primaryKey = 'pro_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'pro_name',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;

    // * Método estático para buscar una promoción por su ID.

    public static function search($promotions){
        $promotion = DB::table('promotions as p')
        ->where('p.pro_id', '=', $promotions)
        ->first();
        return $promotion;
    }
}
