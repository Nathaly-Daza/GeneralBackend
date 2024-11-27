<?php

namespace App\Http\Controllers;

use App\Models\History_Promotion;
use App\Models\Promotion;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class HistoryPromotionController extends Controller
{

    public function index()
    {

        try {
            // Seleccionar todas las historias de promoción
            $history_promotions = History_Promotion::select();

            // Devolver una respuesta JSON con las historias de promoción obtenidas
            return response()->json([
                'status' => true,
                'data' => $history_promotions,
            ], 200);
        } catch (\Throwable $th) {

            // Manejar cualquier excepción que pueda ocurrir durante la obtención de las historias de promoción
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public static function store(Request $request)
    {

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'pro_id' => 'required|integer|exists:promotions',
            'stu_id' => 'required|integer|exists:students',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {

            // Crear una nueva historia de promoción con los datos proporcionados
            $history_promotions = new History_Promotion();
            $history_promotions->pro_id = $request->pro_id;
            $history_promotions->stu_id = $request->stu_id;
            $history_promotions->save();

            // Buscar la promoción asociada a la nueva historia de promoción
            $promotion = Promotion::search($history_promotions->pro_id);

             // Devolver un mensaje de error si no se pudo crear la historia de promoción
            if (!$history_promotions) {
                return response()->json([
                    'status' => False,
                    'message' => $validator->errors()->all()
                ]);
            } else {

                // Disparar la acción de registro
                Controller::NewRegisterTrigger("Se realizo una inserción en la tabla history Promotions", 3, $request->use_id);

                // Devolver una respuesta JSON indicando que se ha añadido la historia de promoción
                return response()->json([
                    'status' => true,
                    'message' => "The history promotions '" . $promotion->pro_name . "' of student '" . $request->stu_id . "' has been added succesfully.",
                ], 200);
            }
        }
    }
    public function show($history_Promotion)
    {

        // Buscar una historia de promoción por su ID
        $history_promotions = History_Promotion::searchPromotions($history_Promotion);

        // Devolver un mensaje de error si no se encuentra la historia de promoción solicitada
        if (!$history_promotions) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the history promotions you are looking for'],
            ], 400);
        } else {

            // Devolver una respuesta JSON con la historia de promoción encontrada
            return response()->json([
                'status' => true,
                'data' => $history_promotions
            ], 200);
        }
    }

    public function update()
    {

        // Devolver un mensaje de error indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }

    public function destroy()
    {

        // Devolver un mensaje de error indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
