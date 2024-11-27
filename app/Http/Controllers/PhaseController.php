<?php

namespace App\Http\Controllers;

use App\Models\Phase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class PhaseController extends Controller
{
    public function index()
    {
        try {
            // Obtener todas las fases desde la base de datos
            $phases = Phase::all();

            // Retornar una respuesta JSON con las fases obtenidas
            return response()->json([
                'status' => true,
                'data' => $phases,
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier error que ocurra y retornar una respuesta JSON con el mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function store(Request $request)
    {
        // Definir reglas de validación para los campos de entrada
        $rules = [
            'pha_name' => 'required|unique:phases|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
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
            // Si la validación pasa, crear una nueva instancia de Phase y guardarla en la base de datos
            $phase = new Phase();
            $phase->pha_name = $request->pha_name;
            $phase->save();

            // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
            Controller::NewRegisterTrigger("Se realizó una inserción en la tabla phases", 3, $request->use_id);

            // Retornar una respuesta JSON indicando que la fase fue agregada exitosamente
            return response()->json([
                'status' => true,
                'message' => "The phase '" . $phase->pha_name . "' has been added successfully."
            ], 200);
        }
    }


    public function show($phase)
    {
        // Buscar la fase por su ID en la base de datos
        $phase = Phase::find($phase);

        // Verificar si la fase no existe y retornar un mensaje de error si es así
        if (!$phase) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the phase you are looking for'],
            ], 400);
        } else {
            // Retornar una respuesta JSON con los detalles de la fase encontrada
            return response()->json([
                'status' => true,
                'data' => $phase,
            ], 200);
        }
    }
    public function update(Request $request, $phase)
    {
        // Definir reglas de validación para los campos de entrada
        $rules = [
            'pha_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];
        // Ejecutar el validador con las reglas definidas

        $validator = Validator::make($request->input(), $rules);
        // Verificar si la validación falla y retornar mensajes de error si es así

        $validate = Controller::validate_exists($request->pha_name, 'phases', 'pha_name', 'pha_id', $phase);

        if ($validator->fails()) {
            // Obtener el mensaje de error personalizado según si el nombre de fase ya existe o no

            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();

            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {
            // Si la validación pasa, actualizar la fase con el nuevo nombre proporcionado

            $phases = Phase::find($phase);
            $phases->pha_name = $request->pha_name;
            $phases->save();
            // Llamar al método estático NewRegisterTrigger para registrar la acción realizada

            Controller::NewRegisterTrigger("Se realizo una edición en la tabla phases", 1, $request->use_id);
            // Retornar una respuesta JSON indicando que la fase fue actualizada exitosamente

            return response()->json([
                'status' => true,
                'data' => "The phase with ID: " . $phases->pha_id . " has been updated to '" . $phases->pha_name . "' succesfully.",
            ], 200);
        }
    }
    public function destroy(Phase $phase)
    {
        // Retorna una respuesta JSON indicando que la función no está disponible para este método
        return response()->json([
            'status' => false,
            'message' => "Function not available."
         ],400);
    }
}
