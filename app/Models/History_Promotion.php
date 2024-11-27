<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class History_Promotion extends Model
{

    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'history_promotions';

    // Clave primaria de la tabla
    protected $primaryKey = 'his_pro_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'pro_id',
        'stu_id'
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;

    // * Método estático para seleccionar todos los registros de historial de promociones con sus relaciones.
    public static function select(){
        $history_promotions = History_Promotion::leftJoin('students', 'history_promotions.stu_id', '=', 'students.stu_id')
        ->leftJoin('promotions', 'history_promotions.pro_id', '=', 'promotions.pro_id')
        ->Join('persons','students.per_id','=',"persons.per_id")
        ->select('history_promotions.his_pro_id', 'persons.per_name','promotions.pro_name')
        ->get();
        return $history_promotions;
    }

    // * Método estático para buscar un registro específico de historial de promoción por su ID.
    public static function search($history_promotions){
        $promotion = DB::table('history_promotions as hp')
        ->select('pro.pro_name', 'p.per_name')
        ->join('students as s', 'hp.stu_id', '=', 's.stu_id')
        ->join('persons as p', 's.per_id', '=', 'p.per_id')
        ->join('promotions as pro', 'hp.pro_id', '=', 'pro.pro_id')
        ->where('hp.his_pro_id', '=', $history_promotions->his_pro_id)
        ->first();
        return $promotion;
    }

    // * Método estático para buscar historial de promoción filtrado por el ID de la persona.
    public static function searchPromotions($history_Promotion){
        $history_promotions = History_Promotion::leftJoin('students', 'history_promotions.stu_id', '=', 'students.stu_id')
        ->leftJoin('promotions', 'history_promotions.pro_id', '=', 'promotions.pro_id')
        ->Join('persons','students.per_id','=',"persons.per_id")
        ->select('history_promotions.his_pro_id', 'persons.per_name','promotions.pro_name')
        ->where('students.per_id','=',$history_Promotion)
        ->first();
        return $history_promotions;
    }
}
