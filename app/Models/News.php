<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class News extends Model
{
    use HasFactory;
    //=========IMPORTANTE ADAPTAR AL MODELO=============
    // Define la clave primaria personalizada
    protected $primaryKey = 'new_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'new_date',
        'new_type_id',
        'proj_id',
        'use_id',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;

    // * Método estático para obtener todas las noticias con información transformada.
    public static function select()
    {
        // Consulta a la vista 'ViewNews' y selecciona los campos deseados

        $news = DB::table('ViewNews')->select(['new_id', 'new_date', 'new_description', 'new_typ_id', 'new_typ_name', 'proj_id', 'proj_name', 'use_id', 'use_mail', 'per_name'])->get();
        // Transforma los resultados obtenidos para un formato más legible

        $transformedNews = $news->map(function ($item) {
            return [
                'id' => $item->new_id,
                'Fecha' => $item->new_date,
                'Descripcion' => $item->new_description,
                'Id novedad' => $item->new_typ_id,
                'Nombre novedad' => $item->new_typ_name,
                'Id proyecto' => $item->proj_id,
                'Nombre proyecto' => $item->proj_name,
                'Id del usuario' => $item->use_id,
                'Correo usuario' => $item->use_mail,
                'nombre persona' => $item->per_name,
            ];
        });

        return $transformedNews;
    }
}
