<?php

namespace App\Http\Controllers;

use App\Models\Vinculation_Type;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class VinculationTypeController extends Controller
{
    public function index()
    {
        try {
            // Obtener todos los tipos de vinculación
            $vinculation_types = Vinculation_Type::all();

            // Retornar una respuesta JSON con estado verdadero y datos de los tipos de vinculación
            return response()->json([
                'status' => true,
                'data' => $vinculation_types,
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier excepción y devolver una respuesta JSON con estado falso y mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }

    public function store(Request $request)
    {
        // Definir reglas de validación para los datos del tipo de vinculación a almacenar
        $rules = [
            'vin_typ_name' => 'required|unique:vinculation_types|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {
            // Retornar una respuesta JSON con estado falso y mensajes de error de validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Crear una nueva instancia de Vinculation_Type con los datos del request
            $vinculation_type = new Vinculation_Type($request->input());
            $vinculation_type->save();

            // Registrar la acción de inserción de tipo de vinculación
            Controller::NewRegisterTrigger("Se realizó una inserción en la tabla vinculation type", 3, $request->use_id);

            // Retornar una respuesta JSON con estado verdadero y mensaje de éxito
            return response()->json([
                'status' => true,
                'message' => "The vinculation type '" . $vinculation_type->vin_typ_name . "' has been added succesfully."
            ], 200);
        }
    }
    public function show($vinculation_Type)
    {
        // Buscar un tipo de vinculación específico por su ID
        $vinculation_type = Vinculation_Type::find($vinculation_Type);

        if (!$vinculation_type) {
            // Retornar una respuesta JSON con estado falso y mensaje de tipo de vinculación no encontrado
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the vinculation types you are looking for'],
            ], 400);
        } else {
            // Retornar una respuesta JSON con estado verdadero y datos del tipo de vinculación encontrado
            return response()->json([
                'status' => true,
                'data' => $vinculation_type,
            ], 200);
        }
    }
    public function update(Request $request, $vinculation_Type)
    {
        // Definir reglas de validación para los datos del tipo de vinculación a actualizar
        $rules = [
            'vin_typ_name' => 'required|string|unique:vinculation_types|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {
            // Retornar una respuesta JSON con estado falso y mensajes de error de validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Buscar el tipo de vinculación a actualizar por su ID
            $vinculation_type = Vinculation_Type::find($vinculation_Type);

            if (!$vinculation_type) {
                // Retornar una respuesta JSON con estado falso y mensaje de tipo de vinculación no encontrado
                return response()->json([
                    'status' => false,
                    'message' => 'Could not find required vinculation type'
                ], 400);
            }

            // Actualizar los datos del tipo de vinculación y guardar los cambios
            $vinculation_type->vin_typ_name = $request->vin_typ_name;
            $vinculation_type->save();

            // Registrar la acción de actualización de tipo de vinculación
            Controller::NewRegisterTrigger("Se realizó una edición en la tabla vinculation type", 1, $request->use_id);

            // Retornar una respuesta JSON con estado verdadero, mensaje de éxito y datos del tipo de vinculación actualizado
            return response()->json([
                'status' => true,
                'data' => "The vinculation type with ID: ". $vinculation_type->vin_typ_id." has been updated to '".$vinculation_type->vin_typ_name."' succesfully.",
            ], 200);
        }
    }
    public function destroy(Vinculation_Type $vinculation_Type)
    {
        // Retornar una respuesta JSON indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
