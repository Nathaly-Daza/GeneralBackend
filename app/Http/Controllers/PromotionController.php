<?php

namespace App\Http\Controllers;

use App\Models\Promotion;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;


use Illuminate\Support\Facades\Validator;

class PromotionController extends Controller
{
    public function index()
    {
        try {
            // Obtener todas las promociones desde la base de datos
            $promotions = Promotion::all();

            // Retornar una respuesta JSON con las promociones obtenidas
            return response()->json([
                'status' => true,
                'data' => $promotions,
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier error que ocurra y retornar una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }

    public function store(Request $request)
    {
        // Definir reglas de validación para los campos de entrada
        $rules = [
            'pro_name' => 'required|string|unique:promotions',
            'use_id' => 'required|integer|exists:users'
        ];

        // Ejecutar el validador con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Verificar si la validación falla y retornar mensajes de error si es así
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Verificar si ya existe una promoción con el mismo nombre y grupo en la base de datos
            $existingPromotion = DB::table('promotions')
                ->where('pro_name', $request->pro_name)
                ->exists();

            // Si la promoción ya existe, retornar un mensaje de error
            if ($existingPromotion) {
                return response()->json([
                    'status' => false,
                    'message' => 'A promotion with the same name already exists.'
                ]);
            } else {
                // Crear una nueva instancia de Promotion y guardarla en la base de datos
                $promotion = new Promotion();
                $promotion->pro_name = $request->pro_name;
                $promotion->save();

                // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
                Controller::NewRegisterTrigger("An insertion was made into the promotions table", 3, $request->use_id);

                // Retornar una respuesta JSON indicando que la promoción fue creada exitosamente
                return response()->json([
                    'status' => true,
                    'message' => "The promotion '" . $promotion->pro_name . "' has been added successfully."
                ], 200);
            }
        }
    }
    
    public function show($promotion)
    {
        // Buscar la promoción por su ID en la base de datos
        $promotions = Promotion::find($promotion);

        // Verificar si la promoción no existe y retornar un mensaje de error si es así
        if (!$promotions) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the promotion you are looking for.'],
            ], 400);
        } else {
            // Retornar una respuesta JSON con los detalles de la promoción encontrada
            return response()->json([
                'status' => true,
                'data' => $promotions,
            ], 200);
        }
    }

    public function update(Request $request, $promotion)
    {
        // Buscar la promoción por su ID en la base de datos
        $promotions = Promotion::find($promotion);

        // Verificar si la promoción no existe y retornar un mensaje de error si es así
        if ($promotions == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The promotion requested was not found']
            ], 400);
        } else {
            // Definir reglas de validación para los campos de entrada
            $rules = [
                'pro_name' => 'required|string',
                'use_id' => 'required|integer|exists:users'
            ];

            // Ejecutar el validador con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar si ya existe otra promoción con el mismo nombre en la base de datos
            $exist = Controller::validate_exists($request->pro_name, 'promotions', 'pro_name', 'pro_id', $promotion);

            // Verificar si la validación falla o si ya existe una promoción con el mismo nombre
            if ($validator->fails() || $exist == 0) {
                $msg = ($exist == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();

                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Si la validación pasa, actualizar la promoción con los nuevos datos proporcionados
                $promotions->pro_name = $request->pro_name;
                $promotions->save();

                // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
                Controller::NewRegisterTrigger("An update was made in the promotions table", 1, $request->use_id);

                // Retornar una respuesta JSON indicando que la promoción fue actualizada exitosamente
                return response()->json([
                    'status' => true,
                    'data' => "The promotion with ID: " . $promotions->pro_id . " has been updated to '" . $promotions->pro_name . "' successfully.",
                ], 200);
            }
        }
    }


    public function destroy()
    {
        // Retorna una respuesta JSON indicando que la función no está disponible para este método
        return response()->json([
            'status' => false,
            'message' => "Function not available."
        ], 400);
    }
}
