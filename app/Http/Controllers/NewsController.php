<?php

namespace App\Http\Controllers;

use App\Models\News;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;


class NewsController extends Controller
{
    public function index()
    {
        try {
            // Intenta seleccionar todas las noticias
            $news = News::select();
            // Devuelve una respuesta JSON con las noticias obtenidas
            return response()->json([
                'status' => true,
                'data' => $news
            ]);
        } catch (\Throwable $th) {
            // Maneja errores y devuelve una respuesta JSON con un mensaje de error
            return response()->json([
              'status' => false,
              'message' => "Error occurred while found elements"
            ],500);
        }
    }

    // Método para mostrar noticias según el tipo, el ID del proyecto y la fecha
    public function show($type, $proj_id, $date)
    {
        try {
            // Busca las noticias en la vista 'ViewNews' filtradas por tipo, ID del proyecto y fecha
            $news = DB::table('ViewNews')
                ->whereDate('new_date', $date)
                ->where('new_typ_id', $type)
                ->where('proj_id', $proj_id)
                ->get();
            // Devuelve una respuesta JSON con las noticias encontradas
            return response()->json([
                'status' => true,
                'data' => $news
            ]);
        } catch (\Throwable $th) {
            // Maneja errores y devuelve una respuesta JSON con un mensaje de error
            return response()->json([
              'status' => false,
              'message' => "Error occurred while found elements"
            ],500);
        }
    }




    
}
