<?php

namespace App\Http\Controllers;

use App\Models\relationships;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class RelationshipsController extends Controller
{
    public function index()
    {
        try {
            // Obtener todas las relaciones desde la base de datos
            $relationships = relationships::all();

            // Retornar una respuesta JSON con las relaciones obtenidas
            return response()->json([
                'status' => true,
                'data' => $relationships
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier error que ocurra y retornar una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => "Error occurred while finding elements."
            ], 500);
        }
    }
    public function store(Request $request)
    {
        // Definir reglas de validación para los campos de entrada
        $rules = [
            'rel_name' => 'required|string|min:1|max:255|unique:relationships|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' =>'required|integer|exists:users'
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
            // Crear una nueva instancia de Relationship y guardarla en la base de datos
            $relationship = new relationships($request->input());
            $relationship->save();

            // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
            Controller::NewRegisterTrigger("A record was created in the relationships table: $request->rel_name", 3, $request->use_id);

            // Retornar una respuesta JSON indicando que la relación fue creada exitosamente
            return response()->json([
                'status' => true,
                'message' => "The relationship: ".$relationship->rel_name." has been created."
            ], 200);
        }
    }
     public function show($id)
    {
        // Buscar la relación por su ID en la base de datos
        $relationship = relationships::find($id);

        // Verificar si la relación no existe y retornar un mensaje de error si es así
        if ($relationship == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The Relationship requested was not found']
            ], 400);
        } else {
            // Retornar una respuesta JSON con los detalles de la relación encontrada
            return response()->json([
                'status' => true,
                'data' => $relationship
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {
        // Buscar la relación por su ID en la base de datos
        $relationship = relationships::find($id);

        // Verificar si la relación no existe y retornar un mensaje de error si es así
        if ($relationship == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The Relationship requested was not found']
            ]);
        } else {
            // Definir reglas de validación para los campos de entrada
            $rules = [
                'rel_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'use_id' =>'required|integer|exists:users'
            ];

            // Ejecutar el validador con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar si ya existe otra relación con el mismo nombre en la base de datos
            $exist = Controller::validate_exists($request->rel_name, 'relationships', 'rel_name', 'rel_id', $id);

            // Verificar si la validación falla o si ya existe una relación con el mismo nombre
            if ($validator->fails() || $exist == 0) {
                $msg = ($exist == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();

                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Si la validación pasa, actualizar la relación con los nuevos datos proporcionados
                $relationship->rel_name = $request->rel_name;
                $relationship->save();

                // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
                Controller::NewRegisterTrigger("An update was made in the relationships table for relationship ID: $id with new data: $request->rel_name", 1, $request->use_id);

                // Retornar una respuesta JSON indicando que la relación fue actualizada exitosamente
                return response()->json([
                    'status' => true,
                    'message' => "The Relationship ".$relationship->rel_name." has been updated successfully."
                ], 200);
            }
        }
    }
    public function destroy(relationships $relationship)
    {
        // Retorna una respuesta JSON indicando que la función no está disponible para este método
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE."
        ], 400);
    }
}
